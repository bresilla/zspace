const std = @import("std");

pub const NamespaceIds = struct {
    user: ?u64 = null,
    pid: ?u64 = null,
    net: ?u64 = null,
    mount: ?u64 = null,
    uts: ?u64 = null,
    ipc: ?u64 = null,
};

pub fn emitSpawned(fd: i32, pid: std.posix.pid_t, ns_ids: NamespaceIds) !void {
    const ts = std.time.timestamp();

    var file = std.fs.File{ .handle = fd };
    var writer = file.deprecatedWriter();

    try writer.print("{{\"event\":\"spawned\",\"pid\":{},\"ts\":{},\"ns\":{{", .{ pid, ts });
    try writeOptionalU64(writer, "user", ns_ids.user);
    try writer.print(",", .{});
    try writeOptionalU64(writer, "pid", ns_ids.pid);
    try writer.print(",", .{});
    try writeOptionalU64(writer, "net", ns_ids.net);
    try writer.print(",", .{});
    try writeOptionalU64(writer, "mount", ns_ids.mount);
    try writer.print(",", .{});
    try writeOptionalU64(writer, "uts", ns_ids.uts);
    try writer.print(",", .{});
    try writeOptionalU64(writer, "ipc", ns_ids.ipc);
    try writer.print("}}}}\n", .{});
}

pub fn emitExited(fd: i32, pid: std.posix.pid_t, exit_code: u8) !void {
    const ts = std.time.timestamp();

    var file = std.fs.File{ .handle = fd };
    var writer = file.deprecatedWriter();
    try writer.print("{{\"event\":\"exited\",\"pid\":{},\"exit_code\":{},\"ts\":{}}}\n", .{ pid, exit_code, ts });
}

pub fn queryNamespaceIds(pid: std.posix.pid_t) !NamespaceIds {
    return .{
        .user = try readNamespaceId(pid, "user"),
        .pid = try readNamespaceId(pid, "pid"),
        .net = try readNamespaceId(pid, "net"),
        .mount = try readNamespaceId(pid, "mnt"),
        .uts = try readNamespaceId(pid, "uts"),
        .ipc = try readNamespaceId(pid, "ipc"),
    };
}

fn readNamespaceId(pid: std.posix.pid_t, name: []const u8) !?u64 {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/proc/{}/ns/{s}", .{ pid, name });

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link = std.fs.readLinkAbsolute(path, &link_buf) catch return null;
    return parseNamespaceInode(link);
}

fn parseNamespaceInode(link: []const u8) ?u64 {
    const start = std.mem.indexOfScalar(u8, link, '[') orelse return null;
    const end = std.mem.indexOfScalarPos(u8, link, start + 1, ']') orelse return null;
    if (end <= start + 1) return null;
    return std.fmt.parseInt(u64, link[start + 1 .. end], 10) catch null;
}

fn writeOptionalU64(writer: anytype, key: []const u8, value: ?u64) !void {
    if (value) |v| {
        try writer.print("\"{s}\":{}", .{ key, v });
    } else {
        try writer.print("\"{s}\":null", .{key});
    }
}

test "parseNamespaceInode parses inode from namespace link" {
    try std.testing.expectEqual(@as(?u64, 4026532000), parseNamespaceInode("net:[4026532000]"));
    try std.testing.expectEqual(@as(?u64, null), parseNamespaceInode("invalid"));
}
