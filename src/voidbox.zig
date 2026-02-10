const std = @import("std");
const Container = @import("container.zig");
const config = @import("config.zig");
const doctor = @import("doctor.zig");
const runtime = @import("runtime.zig");

pub const JailConfig = config.JailConfig;
pub const ShellConfig = config.ShellConfig;
pub const IsolationOptions = config.IsolationOptions;
pub const ResourceLimits = config.ResourceLimits;
pub const ProcessOptions = config.ProcessOptions;
pub const EnvironmentEntry = config.EnvironmentEntry;
pub const RunOutcome = config.RunOutcome;
pub const default_shell_config = config.default_shell_config;
pub const DoctorReport = doctor.DoctorReport;

pub const Session = struct {
    container: Container,
    pid: std.posix.pid_t,
    waited: bool = false,

    pub fn deinit(self: *Session) void {
        self.container.deinit();
    }
};

pub fn launch(jail_config: JailConfig, allocator: std.mem.Allocator) !RunOutcome {
    var session = try spawn(jail_config, allocator);
    defer session.deinit();
    return wait(&session);
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
        .process = shell_config.process,
    };

    return launch(jail_config, allocator);
}

pub fn check_host(allocator: std.mem.Allocator) !DoctorReport {
    return doctor.check(allocator);
}

pub fn spawn(jail_config: JailConfig, allocator: std.mem.Allocator) !Session {
    try runtime.init();
    var container = try Container.init(jail_config, allocator);
    const pid = try container.spawn();

    return .{
        .container = container,
        .pid = pid,
    };
}

pub fn wait(session: *Session) !RunOutcome {
    if (session.waited) return error.SessionAlreadyWaited;

    try session.container.wait(session.pid);
    session.waited = true;
    return .{ .pid = session.pid, .exit_code = 0 };
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
