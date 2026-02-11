const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport({
    @cInclude("signal.h");
    @cInclude("sys/wait.h");
});
const Net = @import("network.zig");
const Cgroup = @import("cgroup.zig");
const Fs = @import("fs.zig");
const namespace = @import("namespace.zig");
const namespace_sequence = @import("namespace_sequence.zig");
const process_exec = @import("process_exec.zig");
const JailConfig = @import("config.zig").JailConfig;
const IsolationOptions = @import("config.zig").IsolationOptions;
const NamespaceFds = @import("config.zig").NamespaceFds;
const ProcessOptions = @import("config.zig").ProcessOptions;
const RuntimeOptions = @import("config.zig").RuntimeOptions;
const SecurityOptions = @import("config.zig").SecurityOptions;
const StatusOptions = @import("config.zig").StatusOptions;

const ChildProcessArgs = struct {
    container: *Container,
    pipe: [2]i32,
    uid: linux.uid_t,
    gid: linux.gid_t,
};

const Container = @This();
name: []const u8,
cmd: []const []const u8,
isolation: IsolationOptions,
namespace_fds: NamespaceFds,
process: ProcessOptions,
runtime: RuntimeOptions,
security: SecurityOptions,
status: StatusOptions,

fs: Fs,
net: ?Net,
cgroup: Cgroup,
allocator: std.mem.Allocator,

pub fn init(run_args: JailConfig, allocator: std.mem.Allocator) !Container {
    return .{
        .name = run_args.name,
        .fs = Fs.init(run_args.rootfs_path, run_args.fs_actions),
        .cmd = run_args.cmd,
        .isolation = run_args.isolation,
        .namespace_fds = run_args.namespace_fds,
        .process = run_args.process,
        .runtime = run_args.runtime,
        .security = run_args.security,
        .status = run_args.status,
        .net = if (run_args.isolation.net) try Net.init(allocator, run_args.name) else null,
        .allocator = allocator,
        .cgroup = try Cgroup.init(run_args.name, run_args.resources, allocator),
    };
}

fn initNetwork(self: *Container) !void {
    if (self.net) |*net| {
        try net.enableNat();
        try net.setUpBridge();
        try net.createVethPair();
        try net.setupDnsResolverConfig(self.fs.rootfs);
    }
}

fn sethostname(self: *Container) void {
    const value = self.runtime.hostname orelse self.name;
    _ = linux.syscall2(.sethostname, @intFromPtr(value.ptr), value.len);
}

pub fn run(self: *Container) !linux.pid_t {
    const pid = try self.spawn();
    _ = try self.wait(pid);
    return pid;
}

pub fn spawn(self: *Container) !linux.pid_t {
    // setup network virtual interfaces and namespace
    try self.initNetwork();

    var childp_args = ChildProcessArgs{
        .container = self,
        .pipe = undefined,
        .uid = self.runtime.uid orelse if (self.isolation.user or self.namespace_fds.user != null) 0 else linux.getuid(),
        .gid = self.runtime.gid orelse if (self.isolation.user or self.namespace_fds.user != null) 0 else linux.getgid(),
    };
    try checkErr(linux.pipe(&childp_args.pipe), error.Pipe);
    var stack = try self.allocator.alloc(u8, 1024 * 1024);
    var ctid: i32 = 0;
    var ptid: i32 = 0;
    const clone_flags = namespace.computeCloneFlags(self.isolation);
    const clone_res = linux.clone(childFn, @intFromPtr(&stack[0]) + stack.len, clone_flags, @intFromPtr(&childp_args), &ptid, 0, &ctid);
    try checkErr(clone_res, error.CloneFailed);

    const pid_signed: isize = @bitCast(clone_res);
    if (pid_signed <= 0) return error.CloneFailed;
    const pid: linux.pid_t = @intCast(pid_signed);
    _ = linux.close(childp_args.pipe[0]);

    // move one of the veth pairs to
    // the child process network namespace
    if (self.net) |*net| {
        try net.moveVethToNs(pid);
    }
    // enter container cgroup
    try self.cgroup.enterCgroup(pid);

    if (self.status.userns_block_fd) |fd| {
        try waitForFd(fd);
    }
    if (self.isolation.user) {
        namespace.writeUserRootMappings(self.allocator, pid) catch |err| {
            _ = linux.close(childp_args.pipe[1]);
            std.posix.kill(pid, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(pid, 0);
            return err;
        };
    }

    // signal done by writing to pipe
    const buff = [_]u8{0};
    _ = try std.posix.write(childp_args.pipe[1], &buff);

    return @intCast(pid);
}

pub fn wait(self: *Container, pid: linux.pid_t) !u8 {
    _ = self;
    const wait_res = std.posix.waitpid(pid, 0);
    return decodeWaitStatus(wait_res.status);
}

// initializes the container environment
// and executes the user passed cmd
fn execCmd(self: *Container, uid: linux.uid_t, gid: linux.gid_t) !void {
    try process_exec.prepare(self.allocator, uid, gid, self.process, self.security, self.namespace_fds);

    self.sethostname();
    try self.fs.setup(self.isolation.mount);
    if (self.process.chdir) |target| {
        std.posix.chdir(target) catch return error.ChdirFailed;
    }
    if (self.net) |*net| {
        if (self.namespace_fds.net != null) {
            // network namespace already attached; skip interface setup
        } else {
            try net.setupContainerVethIf();
        }
    }

    try process_exec.finalizeNamespaces(self.namespace_fds);

    try process_exec.exec(self.allocator, self.cmd, self.process);
}

fn waitForFd(fd: i32) !void {
    var buf: [1]u8 = undefined;
    _ = try std.posix.read(fd, &buf);
}

export fn childFn(a: usize) u8 {
    const arg: *ChildProcessArgs = @ptrFromInt(a);
    _ = linux.close(arg.pipe[1]);
    // block until parent sets up needed resources
    {
        var buff = [_]u8{1};
        _ = std.posix.read(arg.pipe[0], &buff) catch {
            childExit(127);
        };
    }

    if (arg.container.namespace_fds.pid) |pidns_fd| {
        namespace_sequence.preparePidNamespace(pidns_fd, arg.container.isolation.pid) catch {
            childExit(127);
        };

        const pid = std.posix.fork() catch {
            childExit(127);
        };

        if (pid != 0) {
            const wait_res = std.posix.waitpid(pid, 0);
            const code = decodeWaitStatus(wait_res.status) catch 127;
            childExit(code);
        }
    }

    if (arg.container.isolation.pid) {
        if (arg.container.runtime.as_pid_1) {
            arg.container.execCmd(arg.uid, arg.gid) catch {
                childExit(127);
            };
            childExit(0);
        }

        const code = arg.container.execAsPid1(arg.uid, arg.gid) catch {
            childExit(127);
        };
        childExit(code);
    }

    if (arg.container.isolation.user) {
        const code = arg.container.execAsPid1(arg.uid, arg.gid) catch {
            childExit(127);
        };
        childExit(code);
    }

    arg.container.execCmd(arg.uid, arg.gid) catch {
        childExit(127);
    };

    return 0;
}

fn execAsPid1(self: *Container, uid: linux.uid_t, gid: linux.gid_t) !u8 {
    const child_pid = try std.posix.fork();
    if (child_pid == 0) {
        self.execCmd(uid, gid) catch {
            childExit(127);
        };
        childExit(0);
    }

    const wait_res = std.posix.waitpid(child_pid, 0);
    return decodeWaitStatus(wait_res.status);
}

fn childExit(code: u8) noreturn {
    linux.exit(code);
}

fn decodeWaitStatus(status_bits: u32) !u8 {
    const status = @as(c_int, @bitCast(status_bits));
    if (c.WIFEXITED(status)) {
        return @intCast(c.WEXITSTATUS(status));
    }
    if (c.WIFSIGNALED(status)) {
        const sig = c.WTERMSIG(status);
        return @intCast((128 + sig) & 0xff);
    }
    return error.WaitFailed;
}

pub fn deinit(self: *Container) void {
    self.cgroup.deinit() catch |e| {
        log.err("cgroup deinit failed: {}", .{e});
    };
    if (self.net) |*net| {
        net.deinit() catch log.err("net deinit failed", .{});
    }
}
