const std = @import("std");

pub const ResourceLimits = struct {
    mem: ?[]const u8 = null,
    cpu: ?[]const u8 = null,
    pids: ?[]const u8 = null,
};

pub const IsolationOptions = struct {
    net: bool = true,
    mount: bool = true,
    pid: bool = true,
    uts: bool = true,
    ipc: bool = true,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const ProcessOptions = struct {
    chdir: ?[]const u8 = null,
    argv0: ?[]const u8 = null,
    clear_env: bool = false,
    set_env: []const EnvironmentEntry = &.{},
    unset_env: []const []const u8 = &.{},
    new_session: bool = false,
    die_with_parent: bool = false,
};

pub const JailConfig = struct {
    name: []const u8,
    rootfs_path: []const u8,
    cmd: []const []const u8,
    resources: ResourceLimits = .{},
    isolation: IsolationOptions = .{},
    process: ProcessOptions = .{},
};

pub const ShellConfig = struct {
    name: []const u8 = "shell",
    rootfs_path: []const u8,
    shell_path: []const u8 = "/bin/sh",
    shell_args: []const []const u8 = &.{},
    resources: ResourceLimits = .{},
    isolation: IsolationOptions = .{},
    process: ProcessOptions = .{},
};

pub const RunOutcome = struct {
    pid: std.posix.pid_t,
    exit_code: u8,
};

pub fn default_shell_config(rootfs_path: []const u8) ShellConfig {
    return .{ .rootfs_path = rootfs_path };
}
