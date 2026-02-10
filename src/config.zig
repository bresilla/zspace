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

pub const LaunchProfile = enum {
    minimal,
    default,
    full_isolation,
};

pub const MountPair = struct {
    src: []const u8,
    dest: []const u8,
};

pub const TmpfsMount = struct {
    dest: []const u8,
    size_bytes: ?usize = null,
    mode: ?u32 = null,
};

pub const DirAction = struct {
    path: []const u8,
    mode: ?u32 = null,
};

pub const SymlinkAction = struct {
    target: []const u8,
    path: []const u8,
};

pub const ChmodAction = struct {
    path: []const u8,
    mode: u32,
};

pub const FsAction = union(enum) {
    bind: MountPair,
    ro_bind: MountPair,
    proc: []const u8,
    dev: []const u8,
    tmpfs: TmpfsMount,
    dir: DirAction,
    symlink: SymlinkAction,
    chmod: ChmodAction,
    remount_ro: []const u8,
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

pub const SecurityOptions = struct {
    pub const SeccompMode = enum {
        disabled,
        strict,
    };

    no_new_privs: bool = true,
    cap_drop: []const u8 = &.{},
    cap_add: []const u8 = &.{},
    seccomp_mode: SeccompMode = .disabled,
    seccomp_filter_fds: []const i32 = &.{},
};

pub const JailConfig = struct {
    name: []const u8,
    rootfs_path: []const u8,
    cmd: []const []const u8,
    resources: ResourceLimits = .{},
    isolation: IsolationOptions = .{},
    process: ProcessOptions = .{},
    security: SecurityOptions = .{},
    fs_actions: []const FsAction = &.{},
};

pub const ShellConfig = struct {
    name: []const u8 = "shell",
    rootfs_path: []const u8,
    shell_path: []const u8 = "/bin/sh",
    shell_args: []const []const u8 = &.{},
    resources: ResourceLimits = .{},
    isolation: IsolationOptions = .{},
    process: ProcessOptions = .{},
    security: SecurityOptions = .{},
    fs_actions: []const FsAction = &.{},
};

pub const RunOutcome = struct {
    pid: std.posix.pid_t,
    exit_code: u8,
};

pub fn default_shell_config(rootfs_path: []const u8) ShellConfig {
    return .{ .rootfs_path = rootfs_path };
}
