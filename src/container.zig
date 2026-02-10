const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport(@cInclude("signal.h"));
const Net = @import("network.zig");
const Cgroup = @import("cgroup.zig");
const Fs = @import("fs.zig");
const namespace = @import("namespace.zig");
const caps = @import("caps.zig");
const seccomp = @import("seccomp.zig");
const JailConfig = @import("config.zig").JailConfig;
const IsolationOptions = @import("config.zig").IsolationOptions;
const NamespaceFds = @import("config.zig").NamespaceFds;
const ProcessOptions = @import("config.zig").ProcessOptions;
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
    _ = linux.syscall2(.sethostname, @intFromPtr(self.name.ptr), self.name.len);
}

pub fn run(self: *Container) !linux.pid_t {
    const pid = try self.spawn();
    try self.wait(pid);
    return pid;
}

pub fn spawn(self: *Container) !linux.pid_t {
    // setup network virtual interfaces and namespace
    try self.initNetwork();

    var childp_args = ChildProcessArgs{ .container = self, .pipe = undefined, .uid = 0, .gid = 0 };
    try checkErr(linux.pipe(&childp_args.pipe), error.Pipe);
    var stack = try self.allocator.alloc(u8, 1024 * 1024);
    var ctid: i32 = 0;
    var ptid: i32 = 0;
    const clone_flags = namespace.computeCloneFlags(self.isolation);
    const pid = linux.clone(childFn, @intFromPtr(&stack[0]) + stack.len, clone_flags, @intFromPtr(&childp_args), &ptid, 0, &ctid);
    try checkErr(pid, error.CloneFailed);
    std.posix.close(childp_args.pipe[0]);

    // move one of the veth pairs to
    // the child process network namespace
    if (self.net) |*net| {
        try net.moveVethToNs(@intCast(pid));
    }
    // enter container cgroup
    try self.cgroup.enterCgroup(@intCast(pid));

    if (self.status.userns_block_fd) |fd| {
        try waitForFd(fd);
    }
    namespace.writeUserRootMappings(self.allocator, @intCast(pid)) catch @panic("creating root user mapping failed");

    // signal done by writing to pipe
    const buff = [_]u8{0};
    _ = try std.posix.write(childp_args.pipe[1], &buff);

    return @intCast(pid);
}

pub fn wait(self: *Container, pid: linux.pid_t) !void {
    _ = self;
    const wait_res = std.posix.waitpid(pid, 0);
    if (wait_res.status != 0) {
        return error.CmdFailed;
    }
}

// initializes the container environment
// and executes the user passed cmd
fn execCmd(self: *Container, uid: linux.uid_t, gid: linux.gid_t) !void {
    try checkErr(linux.setreuid(uid, uid), error.UID);
    try checkErr(linux.setregid(gid, gid), error.GID);

    try namespace.attach(self.namespace_fds);

    if (self.process.new_session and !std.posix.isatty(std.posix.STDIN_FILENO)) {
        _ = std.posix.setsid() catch return error.SetSidFailed;
    }
    if (self.process.die_with_parent) {
        try checkErr(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @as(usize, @intCast(c.SIGKILL)), 0, 0, 0), error.PrctlFailed);
    }
    if (self.security.no_new_privs) {
        try checkErr(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), error.NoNewPrivsFailed);
    }
    try caps.apply(self.security);
    try seccomp.apply(self.security, self.allocator);

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

    var exec_cmd = self.cmd;
    var owns_exec_cmd = false;
    if (self.process.argv0) |argv0| {
        const cmd_copy = try self.allocator.alloc([]const u8, self.cmd.len);
        @memcpy(cmd_copy, self.cmd);
        cmd_copy[0] = argv0;
        exec_cmd = cmd_copy;
        owns_exec_cmd = true;
    }
    defer if (owns_exec_cmd) self.allocator.free(exec_cmd);

    var env_map = if (self.process.clear_env)
        std.process.EnvMap.init(self.allocator)
    else
        try std.process.getEnvMap(self.allocator);
    defer env_map.deinit();

    for (self.process.unset_env) |key| {
        env_map.remove(key);
    }
    for (self.process.set_env) |entry| {
        try env_map.put(entry.key, entry.value);
    }

    std.process.execve(self.allocator, exec_cmd, &env_map) catch return error.CmdFailed;
}

fn waitForFd(fd: i32) !void {
    var buf: [1]u8 = undefined;
    _ = try std.posix.read(fd, &buf);
}

export fn childFn(a: usize) u8 {
    const arg: *ChildProcessArgs = @ptrFromInt(a);
    std.posix.close(arg.pipe[1]);
    // block until parent sets up needed resources
    {
        var buff = [_]u8{1};
        _ = std.posix.read(arg.pipe[0], &buff) catch @panic("pipe read failed");
    }

    arg.container.execCmd(arg.uid, arg.gid) catch |e| {
        log.err("err: {}", .{e});
        @panic("run failed");
    };

    return 0;
}

pub fn deinit(self: *Container) void {
    self.cgroup.deinit() catch |e| {
        log.err("cgroup deinit failed: {}", .{e});
    };
    if (self.net) |*net| {
        net.deinit() catch log.err("net deinit failed", .{});
    }
}
