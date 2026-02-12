const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;

pub fn makeRootPrivate() !void {
    try checkErr(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0), error.MountPrivate);
}

pub fn enterRoot(rootfs: []const u8) !void {
    const rootfs_z = try std.posix.toPosixPath(rootfs);
    try checkErr(linux.chroot(&rootfs_z), error.Chroot);
    try checkErr(linux.chdir("/"), error.Chdir);
}

pub fn setupDefault() !void {
    try checkErr(linux.mount("proc", "proc", "proc", 0, 0), error.MountProc);
    try checkErr(linux.mount("tmpfs", "tmp", "tmpfs", 0, 0), error.MountTmpFs);
    _ = linux.mount("sysfs", "sys", "sysfs", 0, 0);
}

test "toPosixPath conversion preserves rootfs path" {
    const path = "/tmp/rootfs";
    const path_z = try std.posix.toPosixPath(path);
    const as_slice = std.mem.sliceTo(&path_z, 0);
    try std.testing.expectEqualStrings(path, as_slice);
}
