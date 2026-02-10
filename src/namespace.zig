const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport(@cInclude("signal.h"));

const IsolationOptions = @import("config.zig").IsolationOptions;
const NamespaceFds = @import("config.zig").NamespaceFds;

pub fn computeCloneFlags(isolation: IsolationOptions) u32 {
    var flags: u32 = c.SIGCHLD;
    if (isolation.user) flags |= linux.CLONE.NEWUSER;
    if (isolation.net) flags |= linux.CLONE.NEWNET;
    if (isolation.mount) flags |= linux.CLONE.NEWNS;
    if (isolation.pid) flags |= linux.CLONE.NEWPID;
    if (isolation.uts) flags |= linux.CLONE.NEWUTS;
    if (isolation.ipc) flags |= linux.CLONE.NEWIPC;
    if (isolation.cgroup) flags |= linux.CLONE.NEWCGROUP;
    return flags;
}

pub fn attach(namespace_fds: NamespaceFds) !void {
    if (namespace_fds.mount) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWNS);
    }
    if (namespace_fds.net) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWNET);
    }
    if (namespace_fds.uts) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWUTS);
    }
    if (namespace_fds.ipc) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWIPC);
    }
    if (namespace_fds.pid != null or namespace_fds.user != null) {
        return error.NamespaceAttachNotSupported;
    }
}

pub fn writeUserRootMappings(allocator: std.mem.Allocator, pid: linux.pid_t) !void {
    const uidmap_path = try std.fmt.allocPrint(allocator, "/proc/{}/uid_map", .{pid});
    defer allocator.free(uidmap_path);
    const gidmap_path = try std.fmt.allocPrint(allocator, "/proc/{}/gid_map", .{pid});
    defer allocator.free(gidmap_path);

    const uid_map = try std.fs.openFileAbsolute(uidmap_path, .{ .mode = .write_only });
    defer uid_map.close();
    const gid_map = try std.fs.openFileAbsolute(gidmap_path, .{ .mode = .write_only });
    defer gid_map.close();

    _ = try uid_map.write("0 65534 1");
    _ = try gid_map.write("0 65534 1");
}

fn attachNamespaceFd(fd: i32, nstype: u32) !void {
    const res = linux.syscall2(.setns, @as(usize, @bitCast(@as(isize, fd))), nstype);
    try checkErr(res, error.SetNsFailed);
}

test "computeCloneFlags includes all namespace flags by default" {
    const flags = computeCloneFlags(.{});
    try std.testing.expect((flags & linux.CLONE.NEWUSER) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWNET) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWNS) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWPID) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWUTS) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWIPC) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWCGROUP) == 0);
    try std.testing.expect((flags & c.SIGCHLD) != 0);
}

test "computeCloneFlags respects disabled namespaces" {
    const flags = computeCloneFlags(.{
        .user = false,
        .net = false,
        .mount = false,
        .pid = false,
        .uts = false,
        .ipc = false,
        .cgroup = false,
    });

    try std.testing.expect((flags & linux.CLONE.NEWUSER) == 0);
    try std.testing.expect((flags & c.SIGCHLD) != 0);
    try std.testing.expect((flags & linux.CLONE.NEWNET) == 0);
    try std.testing.expect((flags & linux.CLONE.NEWNS) == 0);
    try std.testing.expect((flags & linux.CLONE.NEWPID) == 0);
    try std.testing.expect((flags & linux.CLONE.NEWUTS) == 0);
    try std.testing.expect((flags & linux.CLONE.NEWIPC) == 0);
    try std.testing.expect((flags & linux.CLONE.NEWCGROUP) == 0);
}
