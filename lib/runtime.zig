const std = @import("std");
const utils = @import("utils.zig");

pub fn init() !void {
    _ = utils.createDirIfNotExists("/var/run/voidbox") catch false;
    _ = utils.createDirIfNotExists("/var/run/voidbox/containers") catch false;
    _ = utils.createDirIfNotExists("/var/run/voidbox/containers/netns") catch false;

    const path = utils.CGROUP_PATH ++ "voidbox/";
    const cgroup_ready = utils.createDirIfNotExists(path) catch false;
    if (!cgroup_ready) return;

    const root_cgroup = path ++ "cgroup.subtree_control";
    var root_cgroup_file = std.fs.openFileAbsolute(root_cgroup, .{ .mode = .write_only }) catch return;
    defer root_cgroup_file.close();
    _ = root_cgroup_file.write("+cpu +memory +pids") catch 0;
}
