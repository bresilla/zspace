const std = @import("std");

pub const DoctorReport = struct {
    is_linux: bool,
    has_user_ns: bool,
    has_mount_ns: bool,
    has_pid_ns: bool,
    has_net_ns: bool,
    has_uts_ns: bool,
    has_ipc_ns: bool,
    cgroup_v2_available: bool,
    iptables_available: bool,
    nft_available: bool,
    unpriv_userns_clone_enabled: ?bool,

    pub fn print(self: DoctorReport, writer: anytype) !void {
        try writer.print("voidbox doctor\n", .{});
        try writer.print("- linux: {}\n", .{self.is_linux});
        try writer.print("- namespaces: user={} mount={} pid={} net={} uts={} ipc={}\n", .{ self.has_user_ns, self.has_mount_ns, self.has_pid_ns, self.has_net_ns, self.has_uts_ns, self.has_ipc_ns });
        try writer.print("- cgroup v2: {}\n", .{self.cgroup_v2_available});
        try writer.print("- net tools: iptables={} nft={}\n", .{ self.iptables_available, self.nft_available });
        if (self.unpriv_userns_clone_enabled) |enabled| {
            try writer.print("- kernel.unprivileged_userns_clone: {}\n", .{enabled});
        } else {
            try writer.print("- kernel.unprivileged_userns_clone: unknown\n", .{});
        }
    }
};

pub fn check(allocator: std.mem.Allocator) !DoctorReport {
    _ = allocator;

    return .{
        .is_linux = true,
        .has_user_ns = ns_exists("/proc/self/ns/user"),
        .has_mount_ns = ns_exists("/proc/self/ns/mnt"),
        .has_pid_ns = ns_exists("/proc/self/ns/pid"),
        .has_net_ns = ns_exists("/proc/self/ns/net"),
        .has_uts_ns = ns_exists("/proc/self/ns/uts"),
        .has_ipc_ns = ns_exists("/proc/self/ns/ipc"),
        .cgroup_v2_available = file_exists("/sys/fs/cgroup/cgroup.controllers"),
        .iptables_available = command_exists("iptables"),
        .nft_available = command_exists("nft"),
        .unpriv_userns_clone_enabled = read_unpriv_userns_clone(),
    };
}

fn ns_exists(path: []const u8) bool {
    return file_exists(path);
}

fn file_exists(path: []const u8) bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

fn command_exists(cmd: []const u8) bool {
    var child = std.process.Child.init(&.{ cmd, "--version" }, std.heap.page_allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    return term.Exited == 0;
}

fn read_unpriv_userns_clone() ?bool {
    const path = "/proc/sys/kernel/unprivileged_userns_clone";
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const content = file.readToEndAlloc(std.heap.page_allocator, 64) catch return null;
    defer std.heap.page_allocator.free(content);

    const trimmed = std.mem.trim(u8, content, " \n\t\r");
    if (std.mem.eql(u8, trimmed, "0")) return false;
    if (std.mem.eql(u8, trimmed, "1")) return true;
    return null;
}
