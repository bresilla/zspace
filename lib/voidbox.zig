//! voidbox is a library-first Linux namespace jail toolkit.
//!
//! Embedder quick start:
//!
//! ```zig
//! const std = @import("std");
//! const voidbox = @import("voidbox");
//!
//! pub fn main() !void {
//!     const allocator = std.heap.page_allocator;
//!     var cfg = voidbox.default_shell_config("/");
//!     cfg.name = "dev-shell";
//!     cfg.shell_args = &.{ "-c", "echo hello from jail" };
//!     cfg.isolation = .{ .user = true, .net = false, .mount = false, .pid = false, .uts = false, .ipc = false };
//!     _ = try voidbox.launch_shell(cfg, allocator);
//! }
//! ```
//!
//! Event callback quick start:
//!
//! ```zig
//! const std = @import("std");
//! const voidbox = @import("voidbox");
//!
//! fn onEvent(ctx: ?*anyopaque, event: voidbox.StatusEvent) !void {
//!     _ = ctx;
//!     _ = event;
//! }
//!
//! pub fn main() !void {
//!     const allocator = std.heap.page_allocator;
//!     const cfg: voidbox.JailConfig = .{
//!         .name = "run-once",
//!         .rootfs_path = "/",
//!         .cmd = &.{ "/bin/sh", "-c", "exit 0" },
//!         .status = .{ .on_event = onEvent },
//!         .isolation = .{ .user = true, .net = false, .mount = false, .pid = false, .uts = false, .ipc = false },
//!     };
//!     _ = try voidbox.launch(cfg, allocator);
//! }
//! ```

const std = @import("std");
const config = @import("config.zig");
const doctor = @import("doctor.zig");
const errors = @import("errors.zig");
const namespace_semantics = @import("namespace_semantics.zig");
const session_api = @import("session.zig");

pub const JailConfig = config.JailConfig;
pub const ShellConfig = config.ShellConfig;
pub const IsolationOptions = config.IsolationOptions;
pub const NamespaceFds = config.NamespaceFds;
pub const ResourceLimits = config.ResourceLimits;
pub const ProcessOptions = config.ProcessOptions;
pub const RuntimeOptions = config.RuntimeOptions;
pub const SecurityOptions = config.SecurityOptions;
pub const SeccompMode = config.SecurityOptions.SeccompMode;
pub const SeccompInstruction = config.SecurityOptions.SeccompInstruction;
pub const StatusOptions = config.StatusOptions;
pub const StatusEvent = config.StatusOptions.Event;
pub const StatusEventKind = config.StatusOptions.EventKind;
pub const StatusNamespaceIds = config.StatusOptions.NamespaceIds;
pub const StatusEventCallback = config.StatusOptions.EventCallback;
pub const EnvironmentEntry = config.EnvironmentEntry;
pub const LaunchProfile = config.LaunchProfile;
pub const FsAction = config.FsAction;
pub const MountPair = config.MountPair;
pub const TmpfsMount = config.TmpfsMount;
pub const DirAction = config.DirAction;
pub const SymlinkAction = config.SymlinkAction;
pub const ChmodAction = config.ChmodAction;
pub const OverlaySource = config.OverlaySource;
pub const OverlayAction = config.OverlayAction;
pub const TmpOverlayAction = config.TmpOverlayAction;
pub const RoOverlayAction = config.RoOverlayAction;
pub const DataBindAction = config.DataBindAction;
pub const FileAction = config.FileAction;
pub const FdDataBindAction = config.FdDataBindAction;
pub const FdFileAction = config.FdFileAction;
pub const RunOutcome = config.RunOutcome;
pub const default_shell_config = config.default_shell_config;
pub const DoctorReport = doctor.DoctorReport;
pub const ValidationError = errors.ValidationError;
pub const SpawnError = errors.SpawnError;
pub const WaitError = errors.WaitError;
pub const LaunchError = errors.LaunchError;
pub const DoctorError = errors.DoctorError;

pub const Session = session_api.Session;

pub fn launch(jail_config: JailConfig, allocator: std.mem.Allocator) LaunchError!RunOutcome {
    var session = try spawn(jail_config, allocator);
    defer session.deinit();
    return wait(&session);
}

pub fn launch_shell(shell_config: ShellConfig, allocator: std.mem.Allocator) LaunchError!RunOutcome {
    const cmd = try build_shell_cmd(shell_config, allocator);
    defer allocator.free(cmd);

    const jail_config: JailConfig = .{
        .name = shell_config.name,
        .rootfs_path = shell_config.rootfs_path,
        .cmd = cmd,
        .resources = shell_config.resources,
        .isolation = shell_config.isolation,
        .namespace_fds = shell_config.namespace_fds,
        .process = shell_config.process,
        .runtime = shell_config.runtime,
        .security = shell_config.security,
        .status = shell_config.status,
        .fs_actions = shell_config.fs_actions,
    };

    return launch(jail_config, allocator);
}

pub fn check_host(allocator: std.mem.Allocator) DoctorError!DoctorReport {
    return doctor.check(allocator) catch return error.DoctorFailed;
}

pub fn with_profile(jail_config: *JailConfig, profile: LaunchProfile) void {
    switch (profile) {
        .minimal => {
            jail_config.isolation = .{
                .user = false,
                .net = false,
                .mount = false,
                .pid = false,
                .uts = false,
                .ipc = false,
                .cgroup = false,
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
            jail_config.isolation = .{ .cgroup = true };
            jail_config.process.new_session = true;
            jail_config.process.die_with_parent = true;
            jail_config.process.clear_env = true;
            jail_config.security.no_new_privs = true;
        },
    }
}

pub fn validate(jail_config: JailConfig) ValidationError!void {
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
    if ((jail_config.runtime.uid != null or jail_config.runtime.gid != null) and
        !jail_config.isolation.user and jail_config.namespace_fds.user == null)
    {
        return error.IdentityRequiresUserNamespace;
    }
    if (jail_config.runtime.hostname) |hostname| {
        if (hostname.len == 0) return error.InvalidHostname;
    }
    if (jail_config.runtime.as_pid_1 and !jail_config.isolation.pid) {
        return error.AsPid1RequiresPidNamespace;
    }
    if (jail_config.security.exec_label != null or jail_config.security.file_label != null) {
        return error.SecurityLabelNotSupported;
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
    if (jail_config.status.info_fd) |fd| {
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

    if (jail_config.namespace_fds.user) |fd| if (fd < 0) return error.InvalidNamespaceFd;
    if (jail_config.namespace_fds.user2) |fd| if (fd < 0) return error.InvalidNamespaceFd;
    if (jail_config.namespace_fds.pid) |fd| if (fd < 0) return error.InvalidNamespaceFd;
    if (jail_config.namespace_fds.net) |fd| if (fd < 0) return error.InvalidNamespaceFd;
    if (jail_config.namespace_fds.mount) |fd| if (fd < 0) return error.InvalidNamespaceFd;
    if (jail_config.namespace_fds.uts) |fd| if (fd < 0) return error.InvalidNamespaceFd;
    if (jail_config.namespace_fds.ipc) |fd| if (fd < 0) return error.InvalidNamespaceFd;

    try namespace_semantics.validate(jail_config.isolation, jail_config.namespace_fds, jail_config.security);

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
    try validateFsTopology(jail_config.fs_actions);
}

fn validateFsAction(action: FsAction) !void {
    switch (action) {
        .perms => |mode| {
            if (mode > 0o7777) return error.InvalidFsMode;
        },
        .size => |val| {
            if (val == 0) return error.InvalidFsSize;
        },
        .bind => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .bind_try => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .dev_bind => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .dev_bind_try => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .ro_bind => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .ro_bind_try => |pair| {
            if (pair.src.len == 0) return error.InvalidFsSource;
            if (pair.dest.len == 0) return error.InvalidFsDestination;
        },
        .proc => |dest| {
            if (dest.len == 0) return error.InvalidFsDestination;
        },
        .dev => |dest| {
            if (dest.len == 0) return error.InvalidFsDestination;
        },
        .mqueue => |dest| {
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
        .overlay_src => |src| {
            if (src.key.len == 0) return error.InvalidOverlaySourceKey;
            if (src.path.len == 0) return error.InvalidFsSource;
        },
        .overlay => |o| {
            if (o.source_key.len == 0) return error.InvalidOverlaySourceKey;
            if (o.upper.len == 0 or o.work.len == 0) return error.InvalidOverlayPath;
            if (o.dest.len == 0) return error.InvalidFsDestination;
        },
        .tmp_overlay => |o| {
            if (o.source_key.len == 0) return error.InvalidOverlaySourceKey;
            if (o.dest.len == 0) return error.InvalidFsDestination;
        },
        .ro_overlay => |o| {
            if (o.source_key.len == 0) return error.InvalidOverlaySourceKey;
            if (o.dest.len == 0) return error.InvalidFsDestination;
        },
        .bind_data => |b| {
            if (b.dest.len == 0) return error.InvalidFsDestination;
        },
        .ro_bind_data => |b| {
            if (b.dest.len == 0) return error.InvalidFsDestination;
        },
        .file => |f| {
            if (f.path.len == 0) return error.InvalidFsDestination;
        },
        .bind_data_fd => |b| {
            if (b.dest.len == 0) return error.InvalidFsDestination;
            if (b.fd < 0) return error.InvalidFsFd;
        },
        .ro_bind_data_fd => |b| {
            if (b.dest.len == 0) return error.InvalidFsDestination;
            if (b.fd < 0) return error.InvalidFsFd;
        },
        .file_fd => |f| {
            if (f.path.len == 0) return error.InvalidFsDestination;
            if (f.fd < 0) return error.InvalidFsFd;
        },
    }
}

fn validateFsTopology(actions: []const FsAction) !void {
    for (actions, 0..) |action, idx| {
        switch (action) {
            .overlay_src => |src| {
                if (overlaySourceSeenBefore(actions, idx, src.key)) {
                    return error.DuplicateOverlaySourceKey;
                }
            },
            .overlay => |o| {
                if (!overlaySourceSeenBefore(actions, idx + 1, o.source_key)) {
                    return error.MissingOverlaySource;
                }
            },
            .tmp_overlay => |o| {
                if (!overlaySourceSeenBefore(actions, idx + 1, o.source_key)) {
                    return error.MissingOverlaySource;
                }
            },
            .ro_overlay => |o| {
                if (!overlaySourceSeenBefore(actions, idx + 1, o.source_key)) {
                    return error.MissingOverlaySource;
                }
            },
            else => {},
        }
    }
}

fn overlaySourceSeenBefore(actions: []const FsAction, end_exclusive: usize, key: []const u8) bool {
    var i: usize = 0;
    while (i < end_exclusive and i < actions.len) : (i += 1) {
        switch (actions[i]) {
            .overlay_src => |src| if (std.mem.eql(u8, src.key, key)) return true,
            else => {},
        }
    }
    return false;
}

pub fn spawn(jail_config: JailConfig, allocator: std.mem.Allocator) SpawnError!Session {
    try validate(jail_config);
    return session_api.spawn(jail_config, allocator) catch |err| switch (err) {
        error.RuntimeInitWarning => error.RuntimeInitWarning,
        error.UserNsNotDisabled => error.UserNsNotDisabled,
        error.UserNsStateUnknown => error.UserNsStateUnknown,
        else => error.SpawnFailed,
    };
}

pub fn wait(session: *Session) WaitError!RunOutcome {
    return session_api.wait(session) catch |err| switch (err) {
        error.SessionAlreadyWaited => error.SessionAlreadyWaited,
        else => error.WaitFailed,
    };
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

test "with_profile full_isolation sets hardened defaults" {
    var cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
    };

    with_profile(&cfg, .full_isolation);

    try std.testing.expect(cfg.isolation.user);
    try std.testing.expect(cfg.isolation.net);
    try std.testing.expect(cfg.isolation.mount);
    try std.testing.expect(cfg.isolation.pid);
    try std.testing.expect(cfg.isolation.uts);
    try std.testing.expect(cfg.isolation.ipc);
    try std.testing.expect(cfg.isolation.cgroup);
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

test "validate rejects malformed try-bind fs action" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{.{ .bind_try = .{ .src = "", .dest = "/x" } }},
    };

    try std.testing.expectError(error.InvalidFsSource, validate(cfg));
}

test "validate rejects invalid fs size modifier" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{.{ .size = 0 }},
    };

    try std.testing.expectError(error.InvalidFsSize, validate(cfg));
}

test "validate requires user namespace for explicit uid/gid" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .user = false },
        .runtime = .{ .uid = 1000 },
    };

    try std.testing.expectError(error.IdentityRequiresUserNamespace, validate(cfg));
}

test "validate rejects empty runtime hostname" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .runtime = .{ .hostname = "" },
    };

    try std.testing.expectError(error.InvalidHostname, validate(cfg));
}

test "validate requires pid namespace for as_pid_1" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .pid = false },
        .runtime = .{ .as_pid_1 = true },
    };

    try std.testing.expectError(error.AsPid1RequiresPidNamespace, validate(cfg));
}

test "validate rejects invalid fd-based fs action" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{.{ .file_fd = .{ .path = "/x", .fd = -1 } }},
    };

    try std.testing.expectError(error.InvalidFsFd, validate(cfg));
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
    try std.testing.expect(!cfg.isolation.user);
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

test "validate rejects invalid info fd" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .status = .{ .info_fd = -1 },
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

test "validate rejects invalid namespace fd" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .namespace_fds = .{ .net = -1 },
    };

    try std.testing.expectError(error.InvalidNamespaceFd, validate(cfg));
}

test "validate rejects invalid userns2 fd" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .namespace_fds = .{ .user2 = -1 },
    };

    try std.testing.expectError(error.InvalidNamespaceFd, validate(cfg));
}

test "validate rejects namespace attach conflict" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .net = true },
        .namespace_fds = .{ .net = 3 },
    };

    try std.testing.expectError(error.NamespaceAttachConflict, validate(cfg));
}

test "validate accepts attached user namespace when unshare user disabled" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .user = false },
        .namespace_fds = .{ .user = 3 },
    };

    try validate(cfg);
}

test "validate accepts attached pid namespace when unshare pid disabled" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .pid = false },
        .namespace_fds = .{ .pid = 3 },
    };

    try validate(cfg);
}

test "validate accepts attached pid namespace with unshare pid" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .pid = true },
        .namespace_fds = .{ .pid = 3 },
    };

    try validate(cfg);
}

test "validate rejects assert-userns-disabled conflict" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .security = .{ .assert_userns_disabled = true },
        .isolation = .{ .user = true },
    };

    try std.testing.expectError(error.AssertUserNsDisabledConflict, validate(cfg));
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
        .k = std.os.linux.SECCOMP.RET.ALLOW,
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
        .k = std.os.linux.SECCOMP.RET.ALLOW,
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
        .k = std.os.linux.SECCOMP.RET.ALLOW,
    }};
    const allow_all_b = [_]SeccompInstruction{.{
        .code = 0x06,
        .jt = 0,
        .jf = 0,
        .k = std.os.linux.SECCOMP.RET.ALLOW,
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

test "validate accepts overlay source topology" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{
            .{ .overlay_src = .{ .key = "base", .path = "/layers/base" } },
            .{ .ro_overlay = .{ .source_key = "base", .dest = "/" } },
        },
    };

    try validate(cfg);
}

test "validate rejects missing overlay source" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{
            .{ .ro_overlay = .{ .source_key = "base", .dest = "/" } },
        },
    };

    try std.testing.expectError(error.MissingOverlaySource, validate(cfg));
}

test "validate rejects duplicate overlay source keys" {
    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/tmp/rootfs",
        .cmd = &.{"/bin/sh"},
        .fs_actions = &.{
            .{ .overlay_src = .{ .key = "base", .path = "/layers/a" } },
            .{ .overlay_src = .{ .key = "base", .path = "/layers/b" } },
        },
    };

    try std.testing.expectError(error.DuplicateOverlaySourceKey, validate(cfg));
}

test "public API compile-time surface" {
    comptime {
        const api = @This();

        std.debug.assert(@hasDecl(api, "JailConfig"));
        std.debug.assert(@hasDecl(api, "ShellConfig"));
        std.debug.assert(@hasDecl(api, "Session"));
        std.debug.assert(@hasDecl(api, "RunOutcome"));
        std.debug.assert(@hasDecl(api, "DoctorReport"));

        std.debug.assert(@hasDecl(api, "launch"));
        std.debug.assert(@hasDecl(api, "spawn"));
        std.debug.assert(@hasDecl(api, "wait"));
        std.debug.assert(@hasDecl(api, "launch_shell"));
        std.debug.assert(@hasDecl(api, "check_host"));
        std.debug.assert(@hasDecl(api, "with_profile"));
        std.debug.assert(@hasDecl(api, "validate"));
        std.debug.assert(@hasDecl(api, "default_shell_config"));

        _ = @as(fn (JailConfig, std.mem.Allocator) anyerror!RunOutcome, launch);
        _ = @as(fn (JailConfig, std.mem.Allocator) anyerror!Session, spawn);
        _ = @as(fn (*Session) anyerror!RunOutcome, wait);
        _ = @as(fn (ShellConfig, std.mem.Allocator) anyerror!RunOutcome, launch_shell);
        _ = @as(fn (std.mem.Allocator) anyerror!DoctorReport, check_host);
        _ = @as(fn (*JailConfig, LaunchProfile) void, with_profile);
        _ = @as(fn (JailConfig) anyerror!void, validate);
        _ = @as(fn ([]const u8) ShellConfig, default_shell_config);
    }
}

test "integration smoke launch_shell happy path" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    var shell_cfg = default_shell_config("/");
    shell_cfg.name = "itest-shell";
    shell_cfg.shell_args = &.{ "-c", "exit 0" };
    shell_cfg.isolation = .{
        .net = false,
        .mount = false,
        .pid = false,
        .uts = false,
        .ipc = false,
    };

    const outcome = try launch_shell(shell_cfg, std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);
}

test "integration smoke launch with net disabled" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const cfg: JailConfig = .{
        .name = "itest-netless",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 0" },
        .isolation = .{
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
        },
    };

    const outcome = try launch(cfg, std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);
}

test "integration smoke launch with selected namespace toggles" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const cfg: JailConfig = .{
        .name = "itest-toggles",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 0" },
        .isolation = .{
            .net = false,
            .mount = false,
            .pid = true,
            .uts = true,
            .ipc = false,
        },
    };

    const outcome = launch(cfg, std.testing.allocator) catch |err| switch (err) {
        error.SpawnFailed => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);
}

test "integration smoke cgroup limits application" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const cfg: JailConfig = .{
        .name = "itest-cgroup",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 0" },
        .resources = .{
            .pids = "32",
        },
        .isolation = .{
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
        },
    };

    const outcome = launch(cfg, std.testing.allocator) catch |err| switch (err) {
        error.SpawnFailed => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);
}

test "integration smoke propagates child exit code" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const cfg: JailConfig = .{
        .name = "itest-exit-code",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 42" },
        .isolation = .{
            .user = false,
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
    };

    const outcome = launch(cfg, std.testing.allocator) catch |err| switch (err) {
        error.SpawnFailed => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectEqual(@as(u8, 42), outcome.exit_code);
}

test "integration stress sequential netless launches" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const iterations: usize = 16;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const cfg: JailConfig = .{
            .name = "itest-stress-netless",
            .rootfs_path = "/",
            .cmd = &.{ "/bin/sh", "-c", "exit 0" },
            .isolation = .{
                .user = false,
                .net = false,
                .mount = false,
                .pid = false,
                .uts = false,
                .ipc = false,
                .cgroup = false,
            },
        };

        const outcome = launch(cfg, std.testing.allocator) catch |err| switch (err) {
            error.SpawnFailed => return error.SkipZigTest,
            else => return err,
        };
        try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);
    }
}

test "integration status callback preserves lifecycle ordering" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const Ctx = struct {
        count: usize = 0,
        kinds: [8]StatusEventKind = undefined,
    };

    const Callback = struct {
        fn onEvent(ctx_ptr: ?*anyopaque, event: StatusEvent) !void {
            const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr.?));
            if (ctx.count < ctx.kinds.len) {
                ctx.kinds[ctx.count] = event.kind;
                ctx.count += 1;
            }
        }
    };

    var ctx = Ctx{};
    const cfg: JailConfig = .{
        .name = "itest-status-order",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 0" },
        .status = .{ .on_event = Callback.onEvent, .callback_ctx = &ctx },
        .isolation = .{
            .user = false,
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
    };

    const outcome = launch(cfg, std.testing.allocator) catch |err| switch (err) {
        error.SpawnFailed => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);

    var spawned_at: ?usize = null;
    var setup_at: ?usize = null;
    var exited_at: ?usize = null;
    for (ctx.kinds[0..ctx.count], 0..) |kind, i| {
        if (kind == .spawned and spawned_at == null) spawned_at = i;
        if (kind == .setup_finished and setup_at == null) setup_at = i;
        if (kind == .exited and exited_at == null) exited_at = i;
    }

    try std.testing.expect(spawned_at != null);
    try std.testing.expect(setup_at != null);
    try std.testing.expect(exited_at != null);
    try std.testing.expect(spawned_at.? < setup_at.?);
    try std.testing.expect(setup_at.? < exited_at.?);
}

test "integration spawn/wait session lifecycle enforces single wait" {
    if (!integrationTestsEnabled()) return error.SkipZigTest;

    const cfg: JailConfig = .{
        .name = "itest-session-lifecycle",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 0" },
        .isolation = .{
            .user = false,
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
    };

    var session = spawn(cfg, std.testing.allocator) catch |err| switch (err) {
        error.SpawnFailed => return error.SkipZigTest,
        else => return err,
    };
    defer session.deinit();

    const first = try wait(&session);
    try std.testing.expectEqual(@as(u8, 0), first.exit_code);
    try std.testing.expectError(error.SessionAlreadyWaited, wait(&session));
}

fn integrationTestsEnabled() bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, "VOIDBOX_RUN_INTEGRATION") catch return false;
    defer std.heap.page_allocator.free(value);

    return std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
}
