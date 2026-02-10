const FsAction = @import("config.zig").FsAction;
const fs_actions = @import("fs_actions.zig");
const mounts = @import("mounts.zig");

rootfs: []const u8,
actions: []const FsAction,

const Fs = @This();

pub fn init(rootfs: []const u8, actions: []const FsAction) Fs {
    return .{ .rootfs = rootfs, .actions = actions };
}

pub fn setup(self: *Fs, mount_fs: bool) !void {
    try mounts.enterRoot(self.rootfs);

    if (!mount_fs) return;

    if (self.actions.len == 0) {
        try mounts.setupDefault();
        return;
    }

    try fs_actions.execute(self.actions);
}
