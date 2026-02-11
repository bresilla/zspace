const std = @import("std");
const linux = std.os.linux;

pub const CGROUP_PATH = "/sys/fs/cgroup/";
pub const INFO_PATH = "/var/run/voidbox/containers/";
pub const NETNS_PATH = INFO_PATH ++ "netns/";
pub const BRIDGE_NAME = "voidbox0";

pub fn checkErr(val: usize, err: anyerror) !void {
    const signed: isize = @bitCast(val);
    if (signed < 0 and signed > -4096) {
        const e: std.os.linux.E = @enumFromInt(@as(usize, @intCast(-signed)));
        // we ignore busy errors here because this fn is used
        // to check the error of mount sycalls.
        // busy is returned when the fs being mounted is currently in use
        // which means that it was previously maounted
        if (e == .BUSY) return;
        return err;
    }
}

pub fn createDirIfNotExists(path: []const u8) !bool {
    std.fs.makeDirAbsolute(path) catch |e| {
        return switch (e) {
            error.PathAlreadyExists => false,
            else => e,
        };
    };
    return true;
}

pub fn createFileIfNotExists(path: []const u8) !bool {
    const f = std.fs.createFileAbsolute(path, .{ .exclusive = true }) catch |e| {
        return switch (e) {
            error.PathAlreadyExists => false,
            else => e,
        };
    };
    f.close();
    return true;
}
