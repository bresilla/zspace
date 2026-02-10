const linux = @import("std").os.linux;
const checkErr = @import("utils.zig").checkErr;

pub fn enterRoot(rootfs: []const u8) !void {
    try checkErr(linux.chroot(@ptrCast(rootfs)), error.Chroot);
    try checkErr(linux.chdir("/"), error.Chdir);
}

pub fn setupDefault() !void {
    try checkErr(linux.mount("proc", "proc", "proc", 0, 0), error.MountProc);
    try checkErr(linux.mount("tmpfs", "tmp", "tmpfs", 0, 0), error.MountTmpFs);
    _ = linux.mount("sysfs", "sys", "sysfs", 0, 0);
}
