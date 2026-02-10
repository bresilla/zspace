const std = @import("std");
const utils = @import("utils.zig");

pub fn init() !void {
    _ = try utils.createDirIfNotExists("/var/run/voidbox");
    _ = try utils.createDirIfNotExists("/var/run/voidbox/containers");
    _ = try utils.createDirIfNotExists("/var/run/voidbox/containers/netns");

    const path = utils.CGROUP_PATH ++ "voidbox/";
    if (!try utils.createDirIfNotExists(path)) return;

    const root_cgroup = path ++ "cgroup.subtree_control";
    var root_cgroup_file = try std.fs.openFileAbsolute(root_cgroup, .{ .mode = .write_only });
    defer root_cgroup_file.close();
    _ = try root_cgroup_file.write("+cpu +memory +pids");
}
