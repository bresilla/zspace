const FsAction = @import("config.zig").FsAction;
const fs_actions = @import("fs_actions.zig");
const mounts = @import("mounts.zig");

rootfs: []const u8,
instance_id: []const u8,
actions: []const FsAction,

const Fs = @This();

pub fn init(rootfs: []const u8, instance_id: []const u8, actions: []const FsAction) Fs {
    return .{ .rootfs = rootfs, .instance_id = instance_id, .actions = actions };
}

pub fn setup(self: *Fs, mount_fs: bool) !void {
    try mounts.enterRoot(self.rootfs);

    if (!mount_fs) return;

    try mounts.makeRootPrivate();

    if (self.actions.len == 0) return;

    try fs_actions.execute(self.instance_id, self.actions);
}

pub fn cleanupRuntimeArtifacts(self: *Fs) void {
    fs_actions.cleanupInstanceArtifacts(self.rootfs, self.instance_id);
}
