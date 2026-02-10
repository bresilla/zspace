const std = @import("std");
const Container = @import("container.zig");
const config = @import("config.zig");
const doctor = @import("doctor.zig");
const runtime = @import("runtime.zig");

pub const JailConfig = config.JailConfig;
pub const ShellConfig = config.ShellConfig;
pub const IsolationOptions = config.IsolationOptions;
pub const ResourceLimits = config.ResourceLimits;
pub const RunOutcome = config.RunOutcome;
pub const default_shell_config = config.default_shell_config;
pub const DoctorReport = doctor.DoctorReport;

pub fn launch(jail_config: JailConfig, allocator: std.mem.Allocator) !RunOutcome {
    try runtime.init();
    var container = try Container.init(jail_config, allocator);
    defer container.deinit();

    const pid = try container.run();
    return .{ .pid = pid, .exit_code = 0 };
}

pub fn launch_shell(shell_config: ShellConfig, allocator: std.mem.Allocator) !RunOutcome {
    const cmd = try build_shell_cmd(shell_config, allocator);
    defer allocator.free(cmd);

    const jail_config: JailConfig = .{
        .name = shell_config.name,
        .rootfs_path = shell_config.rootfs_path,
        .cmd = cmd,
        .resources = shell_config.resources,
        .isolation = shell_config.isolation,
    };

    return launch(jail_config, allocator);
}

pub fn check_host(allocator: std.mem.Allocator) !DoctorReport {
    return doctor.check(allocator);
}

fn build_shell_cmd(shell_config: ShellConfig, allocator: std.mem.Allocator) ![]const []const u8 {
    const count = 1 + shell_config.shell_args.len;
    var cmd = try allocator.alloc([]const u8, count);
    cmd[0] = shell_config.shell_path;
    for (shell_config.shell_args, 0..) |arg, idx| {
        cmd[idx + 1] = arg;
    }
    return cmd;
}
