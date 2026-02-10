const std = @import("std");
const Container = @import("container.zig");
const config = @import("config.zig");
const namespace = @import("namespace.zig");
const runtime = @import("runtime.zig");
const status = @import("status.zig");

pub const JailConfig = config.JailConfig;
pub const ShellConfig = config.ShellConfig;
pub const StatusOptions = config.StatusOptions;
pub const RunOutcome = config.RunOutcome;

pub const Session = struct {
    container: Container,
    pid: std.posix.pid_t,
    status: StatusOptions,
    lock_file: ?std.fs.File = null,
    waited: bool = false,

    pub fn deinit(self: *Session) void {
        if (self.lock_file) |f| {
            f.close();
        }
        self.container.deinit();
    }
};

pub fn spawn(jail_config: JailConfig, allocator: std.mem.Allocator) !Session {
    if (jail_config.security.assert_userns_disabled) {
        try namespace.assertUserNsDisabled();
    }

    if (jail_config.status.block_fd) |fd| {
        try waitForFd(fd);
    }

    const lock_file = if (jail_config.status.lock_file_path) |path|
        try openOrCreateFile(path)
    else
        null;

    try runtime.init();
    var container = try Container.init(jail_config, allocator);
    const pid = try container.spawn();

    const ns_ids = status.queryNamespaceIds(pid) catch status.NamespaceIds{};
    try status.emitSpawnedWithOptions(jail_config.status, pid, ns_ids);
    if (jail_config.status.sync_fd) |fd| {
        try signalFd(fd);
    }

    return .{
        .container = container,
        .pid = pid,
        .status = jail_config.status,
        .lock_file = lock_file,
    };
}

pub fn wait(session: *Session) !RunOutcome {
    if (session.waited) return error.SessionAlreadyWaited;

    const exit_code = try session.container.wait(session.pid);
    session.waited = true;
    try status.emitExitedWithOptions(session.status, session.pid, exit_code);
    return .{ .pid = session.pid, .exit_code = exit_code };
}

fn waitForFd(fd: i32) !void {
    var buf: [1]u8 = undefined;
    _ = try std.posix.read(fd, &buf);
}

fn signalFd(fd: i32) !void {
    const buf = [_]u8{1};
    _ = try std.posix.write(fd, &buf);
}

fn openOrCreateFile(path: []const u8) !std.fs.File {
    return std.fs.openFileAbsolute(path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => std.fs.createFileAbsolute(path, .{ .read = true, .truncate = false }),
        else => err,
    };
}

test "signalFd writes supervisor sync byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    try signalFd(pipefds[1]);

    var byte: [1]u8 = undefined;
    _ = try std.posix.read(pipefds[0], &byte);
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "waitForFd consumes supervisor unblock byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    const one = [_]u8{1};
    _ = try std.posix.write(pipefds[1], &one);
    try waitForFd(pipefds[0]);
}
