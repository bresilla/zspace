const std = @import("std");

pub const KernelVersion = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

pub const CapabilityMatrix = struct {
    overlayfs: bool,
    seccomp_filter: bool,
    namespace_attach: bool,
    userns_mapping: bool,
    procfs: bool,
    tmpfs: bool,
    devtmpfs: bool,
};

pub const DoctorReport = struct {
    is_linux: bool,
    kernel_version: ?KernelVersion,
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
    capabilities: CapabilityMatrix,

    pub fn print(self: DoctorReport, writer: anytype) !void {
        try writer.print("voidbox doctor\n", .{});
        try writer.print("- linux: {}\n", .{self.is_linux});
        if (self.kernel_version) |v| {
            try writer.print("- kernel: {}.{}.{}\n", .{ v.major, v.minor, v.patch });
        } else {
            try writer.print("- kernel: unknown\n", .{});
        }
        try writer.print("- namespaces: user={} mount={} pid={} net={} uts={} ipc={}\n", .{ self.has_user_ns, self.has_mount_ns, self.has_pid_ns, self.has_net_ns, self.has_uts_ns, self.has_ipc_ns });
        try writer.print("- cgroup v2: {}\n", .{self.cgroup_v2_available});
        try writer.print("- net tools: iptables={} nft={}\n", .{ self.iptables_available, self.nft_available });
        if (self.unpriv_userns_clone_enabled) |enabled| {
            try writer.print("- kernel.unprivileged_userns_clone: {}\n", .{enabled});
        } else {
            try writer.print("- kernel.unprivileged_userns_clone: unknown\n", .{});
        }
        try writer.print("- capability matrix: overlayfs={} seccomp_filter={} namespace_attach={} userns_mapping={} procfs={} tmpfs={} devtmpfs={}\n", .{
            self.capabilities.overlayfs,
            self.capabilities.seccomp_filter,
            self.capabilities.namespace_attach,
            self.capabilities.userns_mapping,
            self.capabilities.procfs,
            self.capabilities.tmpfs,
            self.capabilities.devtmpfs,
        });
    }
};

pub fn check(allocator: std.mem.Allocator) !DoctorReport {
    const cgroup_v2 = file_exists("/sys/fs/cgroup/cgroup.controllers");
    const filesystems = try readSmallFile(allocator, "/proc/filesystems", 16 * 1024);
    defer if (filesystems) |v| allocator.free(v);

    const overlayfs = if (filesystems) |v| containsToken(v, "overlay") else false;
    const procfs = if (filesystems) |v| containsToken(v, "proc") else false;
    const tmpfs = if (filesystems) |v| containsToken(v, "tmpfs") else false;
    const devtmpfs = if (filesystems) |v| containsToken(v, "devtmpfs") else false;

    return .{
        .is_linux = true,
        .kernel_version = try readKernelVersion(allocator),
        .has_user_ns = ns_exists("/proc/self/ns/user"),
        .has_mount_ns = ns_exists("/proc/self/ns/mnt"),
        .has_pid_ns = ns_exists("/proc/self/ns/pid"),
        .has_net_ns = ns_exists("/proc/self/ns/net"),
        .has_uts_ns = ns_exists("/proc/self/ns/uts"),
        .has_ipc_ns = ns_exists("/proc/self/ns/ipc"),
        .cgroup_v2_available = cgroup_v2,
        .iptables_available = command_exists("iptables"),
        .nft_available = command_exists("nft"),
        .unpriv_userns_clone_enabled = read_unpriv_userns_clone(),
        .capabilities = .{
            .overlayfs = overlayfs,
            .seccomp_filter = file_exists("/proc/sys/kernel/seccomp/actions_avail"),
            .namespace_attach = ns_exists("/proc/self/ns/mnt") and ns_exists("/proc/self/ns/net"),
            .userns_mapping = file_exists("/proc/self/uid_map") and file_exists("/proc/self/gid_map"),
            .procfs = procfs,
            .tmpfs = tmpfs,
            .devtmpfs = devtmpfs,
        },
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

fn readKernelVersion(allocator: std.mem.Allocator) !?KernelVersion {
    const content = try readSmallFile(allocator, "/proc/sys/kernel/osrelease", 128);
    defer if (content) |v| allocator.free(v);
    if (content == null) return null;

    const trimmed = std.mem.trim(u8, content.?, " \n\t\r");
    var it = std.mem.splitScalar(u8, trimmed, '.');
    const major_s = it.next() orelse return null;
    const minor_s = it.next() orelse return null;
    const patch_part = it.next() orelse return null;

    const patch_s = patchDigits(patch_part);
    if (patch_s.len == 0) return null;

    return .{
        .major = std.fmt.parseInt(u32, major_s, 10) catch return null,
        .minor = std.fmt.parseInt(u32, minor_s, 10) catch return null,
        .patch = std.fmt.parseInt(u32, patch_s, 10) catch return null,
    };
}

fn patchDigits(input: []const u8) []const u8 {
    var end: usize = 0;
    while (end < input.len and std.ascii.isDigit(input[end])) : (end += 1) {}
    return input[0..end];
}

fn readSmallFile(allocator: std.mem.Allocator, path: []const u8, limit: usize) !?[]u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    return file.readToEndAlloc(allocator, limit) catch return null;
}

fn containsToken(content: []const u8, token: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, token) != null) return true;
    }
    return false;
}
