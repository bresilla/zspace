const std = @import("std");
const Container = @import("container.zig");
const config = @import("config.zig");
const doctor = @import("doctor.zig");
const runtime = @import("runtime.zig");
const status = @import("status.zig");

pub const JailConfig = config.JailConfig;
pub const ShellConfig = config.ShellConfig;
pub const IsolationOptions = config.IsolationOptions;
pub const ResourceLimits = config.ResourceLimits;
pub const ProcessOptions = config.ProcessOptions;
pub const SecurityOptions = config.SecurityOptions;
pub const SeccompMode = config.SecurityOptions.SeccompMode;
pub const SeccompInstruction = config.SecurityOptions.SeccompInstruction;
pub const StatusOptions = config.StatusOptions;
pub const EnvironmentEntry = config.EnvironmentEntry;
pub const LaunchProfile = config.LaunchProfile;
pub const FsAction = config.FsAction;
pub const MountPair = config.MountPair;
pub const TmpfsMount = config.TmpfsMount;
pub const DirAction = config.DirAction;
pub const SymlinkAction = config.SymlinkAction;
pub const ChmodAction = config.ChmodAction;
pub const RunOutcome = config.RunOutcome;
pub const default_shell_config = config.default_shell_config;
pub const DoctorReport = doctor.DoctorReport;

pub const Session = struct {
    container: Container,
    pid: std.posix.pid_t,
    status: StatusOptions,
    lock_file: ?std.fs.File = null,
    waited: bool = false,

    pub fn deinit(self: *Session) void {
        if (self.lock_file) |f| {
            f.close();
        }
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
        .security = shell_config.security,
        .status = shell_config.status,
        .fs_actions = shell_config.fs_actions,
    };

    return launch(jail_config, allocator);
}

pub fn check_host(allocator: std.mem.Allocator) !DoctorReport {
    return doctor.check(allocator);
}

pub fn with_profile(jail_config: *JailConfig, profile: LaunchProfile) void {
    switch (profile) {
        .minimal => {
            jail_config.isolation = .{
                .net = false,
                .mount = false,
                .pid = false,
                .uts = false,
                .ipc = false,
            };
            jail_config.process.new_session = false;
            jail_config.process.die_with_parent = false;
            jail_config.process.clear_env = false;
        },
        .default => {
            jail_config.isolation = .{};
            jail_config.process.new_session = false;
            jail_config.process.die_with_parent = false;
            jail_config.process.clear_env = false;
        },
        .full_isolation => {
            jail_config.isolation = .{};
            jail_config.process.new_session = true;
            jail_config.process.die_with_parent = true;
            jail_config.process.clear_env = true;
            jail_config.security.no_new_privs = true;
        },
    }
}

pub fn validate(jail_config: JailConfig) !void {
    if (jail_config.name.len == 0) return error.InvalidName;
    if (jail_config.rootfs_path.len == 0) return error.InvalidRootfsPath;
    if (jail_config.cmd.len == 0) return error.MissingCommand;
    if (jail_config.cmd[0].len == 0) return error.InvalidCommand;
    if (jail_config.resources.mem) |v| if (v.len == 0) return error.InvalidMemoryLimit;
    if (jail_config.resources.cpu) |v| if (v.len == 0) return error.InvalidCpuLimit;
    if (jail_config.resources.pids) |v| if (v.len == 0) return error.InvalidPidsLimit;
    if (jail_config.process.argv0) |argv0| {
        if (argv0.len == 0) return error.InvalidArgv0;
    }
    if (jail_config.process.chdir) |chdir_path| {
        if (chdir_path.len == 0) return error.InvalidChdir;
    }

    if (!jail_config.isolation.mount and jail_config.fs_actions.len > 0) {
        return error.FsActionsRequireMountNamespace;
    }

    for (jail_config.process.unset_env) |key| {
        if (key.len == 0) return error.InvalidUnsetEnvKey;
    }
    for (jail_config.process.set_env) |entry| {
        if (entry.key.len == 0) return error.InvalidSetEnvKey;
    }
    if (jail_config.status.json_status_fd) |fd| {
        if (fd < 0) return error.InvalidStatusFd;
    }
    if (jail_config.status.sync_fd) |fd| {
        if (fd < 0) return error.InvalidSyncFd;
    }
    if (jail_config.status.block_fd) |fd| {
        if (fd < 0) return error.InvalidBlockFd;
    }
    if (jail_config.status.userns_block_fd) |fd| {
        if (fd < 0) return error.InvalidUsernsBlockFd;
    }
    if (jail_config.status.lock_file_path) |path| {
        if (path.len == 0) return error.InvalidLockFilePath;
    }

    for (jail_config.security.cap_add) |cap| {
        if (!std.os.linux.CAP.valid(cap)) return error.InvalidCapability;
    }
    for (jail_config.security.cap_drop) |cap| {
        if (!std.os.linux.CAP.valid(cap)) return error.InvalidCapability;
    }
    const has_filters = jail_config.security.seccomp_filter != null or jail_config.security.seccomp_filters.len > 0 or jail_config.security.seccomp_filter_fds.len > 0;
    if (jail_config.security.seccomp_mode == .strict and has_filters) {
        return error.SeccompModeConflict;
    }
    if (jail_config.security.seccomp_filter) |filter| {
        if (filter.len == 0) return error.InvalidSeccompFilter;
    }
    for (jail_config.security.seccomp_filters) |filter| {
        if (filter.len == 0) return error.InvalidSeccompFilter;
    }
    for (jail_config.security.seccomp_filter_fds) |fd| {
        if (fd < 0) return error.InvalidSeccompFilterFd;
    }
    if ((jail_config.security.seccomp_mode == .strict or has_filters) and !jail_config.security.no_new_privs) {
        return error.SeccompRequiresNoNewPrivs;
    }

    for (jail_config.fs_actions) |action| {
        try validateFsAction(action);
    }
}

fn validateFsAction(action: FsAction) !void {
    switch (action) {
        .bind => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .ro_bind => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .proc => |dest| {
            if (dest.len == 0) return error.InvalidFsDestination;
        },
        .dev => |dest| {
            if (dest.len == 0) return error.InvalidFsDestination;
        },
        .tmpfs => |tmpfs| {
            if (tmpfs.dest.len == 0) return error.InvalidFsDestination;
            if (tmpfs.mode) |mode| {
                if (mode > 0o7777) return error.InvalidFsMode;
            }
        },
        .dir => |d| {
            if (d.path.len == 0) return error.InvalidFsDestination;
            if (d.mode) |mode| {
                if (mode > 0o7777) return error.InvalidFsMode;
            }
        },
        .symlink => |s| {
            if (s.path.len == 0) return error.InvalidFsDestination;
            if (s.target.len == 0) return error.InvalidFsSource;
        },
        .chmod => |c| {
            if (c.path.len == 0) return error.InvalidFsDestination;
            if (c.mode > 0o7777) return error.InvalidFsMode;
        },
        .remount_ro => |dest| {
            if (dest.len == 0) return error.InvalidFsDestination;
        },
    }
}

pub fn spawn(jail_config: JailConfig, allocator: std.mem.Allocator) !Session {
    try validate(jail_config);

    if (jail_config.status.block_fd) |fd| {
        try waitForFd(fd);
    }

    const lock_file = if (jail_config.status.lock_file_path) |path|
        try openOrCreateFile(path)
    else
        null;

    try runtime.init();
    var container = try Container.init(jail_config, allocator);
    const pid = try container.spawn();

    if (jail_config.status.json_status_fd) |fd| {
        try status.emitJson(fd, "spawned", pid, null);
    }
    if (jail_config.status.sync_fd) |fd| {
        try signalFd(fd);
    }

    return .{
        .container = container,
        .pid = pid,
        .status = jail_config.status,
        .lock_file = lock_file,
    };
}

pub fn wait(session: *Session) !RunOutcome {
    if (session.waited) return error.SessionAlreadyWaited;

    try session.container.wait(session.pid);
    session.waited = true;
    if (session.status.json_status_fd) |fd| {
        try status.emitJson(fd, "exited", session.pid, 0);
    }
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

fn waitForFd(fd: i32) !void {
    var buf: [1]u8 = undefined;
    _ = try std.posix.read(fd, &buf);
}

fn signalFd(fd: i32) !void {
    const buf = [_]u8{1};
    _ = try std.posix.write(fd, &buf);
}

fn openOrCreateFile(path: []const u8) !std.fs.File {
    return std.fs.openFileAbsolute(path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => std.fs.createFileAbsolute(path, .{ .read = true, .truncate = false }),
        else => err,
    };
}

test "with_profile full_isolation sets hardened defaults" {
    var cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
    };

    with_profile(&cfg, .full_isolation);

    try std.testing.expect(cfg.isolation.net);
    try std.testing.expect(cfg.isolation.mount);
    try std.testing.expect(cfg.isolation.pid);
    try std.testing.expect(cfg.isolation.uts);
    try std.testing.expect(cfg.isolation.ipc);
    try std.testing.expect(cfg.process.new_session);
    try std.testing.expect(cfg.process.die_with_parent);
    try std.testing.expect(cfg.process.clear_env);
}

test "validate rejects empty rootfs" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "",
        .cmd = &.{"/bin/sh"},
    };

    try std.testing.expectError(error.InvalidRootfsPath, validate(cfg));
}

test "validate rejects fs actions when mount isolation disabled" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .mount = false },
        .fs_actions = &.{.{ .proc = "/proc" }},
    };

    try std.testing.expectError(error.FsActionsRequireMountNamespace, validate(cfg));
}

test "validate rejects malformed fs action" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{.{ .bind = .{ .src = "", .dest = "/x" } }},
    };

    try std.testing.expectError(error.InvalidFsSource, validate(cfg));
}

test "full_isolation profile validates with fs actions" {
    var cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{
            .{ .proc = "/proc" },
            .{ .tmpfs = .{ .dest = "/tmp", .mode = 0o1777 } },
        },
    };

    with_profile(&cfg, .full_isolation);
    try validate(cfg);
}

test "minimal profile rejects mount actions" {
    var cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{.{ .proc = "/proc" }},
    };

    with_profile(&cfg, .minimal);
    try std.testing.expectError(error.FsActionsRequireMountNamespace, validate(cfg));
}

test "validate rejects invalid status fd" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .status = .{ .json_status_fd = -1 },
    };

    try std.testing.expectError(error.InvalidStatusFd, validate(cfg));
}

test "validate rejects invalid sync fd" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .status = .{ .sync_fd = -1 },
    };

    try std.testing.expectError(error.InvalidSyncFd, validate(cfg));
}

test "security defaults to no_new_privs" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
    };

    try std.testing.expect(cfg.security.no_new_privs);
}

test "full_isolation enforces no_new_privs" {
    var cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .no_new_privs = false },
    };

    with_profile(&cfg, .full_isolation);
    try std.testing.expect(cfg.security.no_new_privs);
}

test "validate rejects invalid dropped capability" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .cap_drop = &.{255} },
    };

    try std.testing.expectError(error.InvalidCapability, validate(cfg));
}

test "validate rejects invalid added capability" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .cap_add = &.{255} },
    };

    try std.testing.expectError(error.InvalidCapability, validate(cfg));
}

test "validate accepts capability add and drop values" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{
            .cap_add = &.{std.os.linux.CAP.NET_RAW},
            .cap_drop = &.{std.os.linux.CAP.SYS_ADMIN},
        },
    };

    try validate(cfg);
}

test "validate rejects invalid seccomp filter fd" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .seccomp_filter_fds = &.{-1} },
    };

    try std.testing.expectError(error.InvalidSeccompFilterFd, validate(cfg));
}

test "validate requires no_new_privs for seccomp strict" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{
            .no_new_privs = false,
            .seccomp_mode = .strict,
        },
    };

    try std.testing.expectError(error.SeccompRequiresNoNewPrivs, validate(cfg));
}

test "validate rejects conflicting seccomp mode and filter" {
    const allow_all = [_]SeccompInstruction{.{
        .code = 0x06,
        .jt = 0,
        .jf = 0,
        .k = std.os.linux.seccomp.RET.ALLOW,
    }};
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{
            .seccomp_mode = .strict,
            .seccomp_filter = &allow_all,
        },
    };

    try std.testing.expectError(error.SeccompModeConflict, validate(cfg));
}

test "validate rejects empty seccomp filter" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .seccomp_filter = &.{} },
    };

    try std.testing.expectError(error.InvalidSeccompFilter, validate(cfg));
}

test "validate accepts seccomp filter baseline" {
    const allow_all = [_]SeccompInstruction{.{
        .code = 0x06,
        .jt = 0,
        .jf = 0,
        .k = std.os.linux.seccomp.RET.ALLOW,
    }};
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .seccomp_filter = &allow_all },
    };

    try validate(cfg);
}

test "validate accepts stacked seccomp filters" {
    const allow_all_a = [_]SeccompInstruction{.{
        .code = 0x06,
        .jt = 0,
        .jf = 0,
        .k = std.os.linux.seccomp.RET.ALLOW,
    }};
    const allow_all_b = [_]SeccompInstruction{.{
        .code = 0x06,
        .jt = 0,
        .jf = 0,
        .k = std.os.linux.seccomp.RET.ALLOW,
    }};
    const stacked = [_][]const SeccompInstruction{ &allow_all_a, &allow_all_b };

    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .seccomp_filters = &stacked },
    };

    try validate(cfg);
}

test "validate accepts seccomp filter fds" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .seccomp_filter_fds = &.{3} },
    };

    try validate(cfg);
}

test "validate rejects empty stacked seccomp filter" {
    const empty = [_]SeccompInstruction{};
    const stacked = [_][]const SeccompInstruction{&empty};

    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .seccomp_filters = &stacked },
    };

    try std.testing.expectError(error.InvalidSeccompFilter, validate(cfg));
}
