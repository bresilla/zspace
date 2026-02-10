const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport(@cInclude("signal.h"));
const Net = @import("net.zig");
const Cgroup = @import("cgroup.zig");
const Fs = @import("fs.zig");
const JailConfig = @import("config.zig").JailConfig;
const IsolationOptions = @import("config.zig").IsolationOptions;

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

fs: Fs,
net: ?Net,
cgroup: Cgroup,
allocator: std.mem.Allocator,

pub fn init(run_args: JailConfig, allocator: std.mem.Allocator) !Container {
    return .{
        .name = run_args.name,
        .fs = Fs.init(run_args.rootfs_path),
        .cmd = run_args.cmd,
        .isolation = run_args.isolation,
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
    // setup network virtual interfaces and namespace
    try self.initNetwork();

    var childp_args = ChildProcessArgs{ .container = self, .pipe = undefined, .uid = 0, .gid = 0 };
    try checkErr(linux.pipe(&childp_args.pipe), error.Pipe);
    var stack = try self.allocator.alloc(u8, 1024 * 1024);
    var ctid: i32 = 0;
    var ptid: i32 = 0;
    var clone_flags: u32 = linux.CLONE.NEWUSER | c.SIGCHLD;
    if (self.isolation.net) clone_flags |= linux.CLONE.NEWNET;
    if (self.isolation.mount) clone_flags |= linux.CLONE.NEWNS;
    if (self.isolation.pid) clone_flags |= linux.CLONE.NEWPID;
    if (self.isolation.uts) clone_flags |= linux.CLONE.NEWUTS;
    if (self.isolation.ipc) clone_flags |= linux.CLONE.NEWIPC;
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
    self.createUserRootMappings(@intCast(pid)) catch @panic("creating root user mapping failed");

    // signal done by writing to pipe
    const buff = [_]u8{0};
    _ = try std.posix.write(childp_args.pipe[1], &buff);

    const wait_res = std.posix.waitpid(@intCast(pid), 0);
    if (wait_res.status != 0) {
        return error.CmdFailed;
    }

    return @intCast(pid);
}

// initializes the container environment
// and executes the user passed cmd
fn execCmd(self: *Container, uid: linux.uid_t, gid: linux.gid_t) !void {
    try checkErr(linux.setreuid(uid, uid), error.UID);
    try checkErr(linux.setregid(gid, gid), error.GID);

    self.sethostname();
    try self.fs.setup(self.isolation.mount);
    if (self.net) |*net| {
        try net.setupContainerVethIf();
    }

    std.process.execv(self.allocator, self.cmd) catch return error.CmdFailed;
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

fn createUserRootMappings(self: *Container, pid: linux.pid_t) !void {
    const uidmap_path = try std.fmt.allocPrint(self.allocator, "/proc/{}/uid_map", .{pid});
    defer self.allocator.free(uidmap_path);
    const gidmap_path = try std.fmt.allocPrint(self.allocator, "/proc/{}/gid_map", .{pid});
    defer self.allocator.free(gidmap_path);

    const uid_map = try std.fs.openFileAbsolute(uidmap_path, .{ .mode = .write_only });
    defer uid_map.close();
    const gid_map = try std.fs.openFileAbsolute(gidmap_path, .{ .mode = .write_only });
    defer gid_map.close();

    // map root inside user namespace to the "nobody" user and group outside the namespace
    _ = try uid_map.write("0 65534 1");
    _ = try gid_map.write("0 65534 1");
}

pub fn deinit(self: *Container) void {
    self.cgroup.deinit() catch |e| {
        log.err("cgroup deinit failed: {}", .{e});
    };
    if (self.net) |*net| {
        net.deinit() catch log.err("net deinit failed", .{});
    }
}
