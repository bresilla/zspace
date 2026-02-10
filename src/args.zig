const std = @import("std");
const config = @import("config.zig");
const LaunchProfile = config.LaunchProfile;
const EnvironmentEntry = config.EnvironmentEntry;
const SeccompMode = config.SecurityOptions.SeccompMode;
const FsAction = config.FsAction;

inline fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// voidbox run <name> <rootfs_path> <cmd>
pub const RunArgs = struct {
    name: []const u8,
    rootfs_path: []const u8,
    cmd: []const []const u8,
    resources: config.ResourceLimits,
    isolation: config.IsolationOptions,
    process: config.ProcessOptions,
    security: config.SecurityOptions,
    status: config.StatusOptions,
    fs_actions: []const FsAction,
    profile: ?LaunchProfile = null,

    fn parse(allocator: std.mem.Allocator, args: *std.process.ArgIterator) !RunArgs {
        var argv = std.ArrayList([]const u8).empty;
        defer argv.deinit(allocator);

        while (args.next()) |val| {
            try argv.append(allocator, val);
        }

        var resources = config.ResourceLimits{};
        var isolation = config.IsolationOptions{};
        var process = config.ProcessOptions{};
        var security = config.SecurityOptions{};
        var status = config.StatusOptions{};
        var profile: ?LaunchProfile = null;

        var set_env = std.ArrayList(EnvironmentEntry).empty;
        defer set_env.deinit(allocator);
        var unset_env = std.ArrayList([]const u8).empty;
        defer unset_env.deinit(allocator);
        var cap_drop = std.ArrayList(u8).empty;
        defer cap_drop.deinit(allocator);
        var cap_add = std.ArrayList(u8).empty;
        defer cap_add.deinit(allocator);
        var seccomp_fds = std.ArrayList(i32).empty;
        defer seccomp_fds.deinit(allocator);
        var fs_actions = std.ArrayList(FsAction).empty;
        defer fs_actions.deinit(allocator);

        var idx: usize = 0;
        while (idx < argv.items.len) {
            const arg = argv.items[idx];
            if (!std.mem.startsWith(u8, arg, "-")) break;

            if (eql(arg, "-m") or eql(arg, "-mem")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                resources.mem = argv.items[idx];
            } else if (eql(arg, "-c") or eql(arg, "-cpu")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                resources.cpu = argv.items[idx];
            } else if (eql(arg, "-p") or eql(arg, "-pids")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                resources.pids = argv.items[idx];
            } else if (eql(arg, "--no-net")) {
                isolation.net = false;
            } else if (eql(arg, "--no-mount")) {
                isolation.mount = false;
            } else if (eql(arg, "--no-pid")) {
                isolation.pid = false;
            } else if (eql(arg, "--no-uts")) {
                isolation.uts = false;
            } else if (eql(arg, "--no-ipc")) {
                isolation.ipc = false;
            } else if (eql(arg, "--profile")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                profile = parseProfile(argv.items[idx]) orelse return error.InvalidProfile;
            } else if (eql(arg, "--chdir")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                process.chdir = argv.items[idx];
            } else if (eql(arg, "--argv0")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                process.argv0 = argv.items[idx];
            } else if (eql(arg, "--setenv")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try set_env.append(allocator, try parseSetEnv(argv.items[idx]));
            } else if (eql(arg, "--unsetenv")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try unset_env.append(allocator, argv.items[idx]);
            } else if (eql(arg, "--clearenv")) {
                process.clear_env = true;
            } else if (eql(arg, "--new-session")) {
                process.new_session = true;
            } else if (eql(arg, "--die-with-parent")) {
                process.die_with_parent = true;
            } else if (eql(arg, "--no-new-privs")) {
                security.no_new_privs = true;
            } else if (eql(arg, "--allow-new-privs")) {
                security.no_new_privs = false;
            } else if (eql(arg, "--seccomp")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                security.seccomp_mode = parseSeccompMode(argv.items[idx]) orelse return error.InvalidSeccompMode;
            } else if (eql(arg, "--seccomp-fd")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try seccomp_fds.append(allocator, try std.fmt.parseInt(i32, argv.items[idx], 10));
            } else if (eql(arg, "--cap-drop")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try cap_drop.append(allocator, try std.fmt.parseInt(u8, argv.items[idx], 10));
            } else if (eql(arg, "--cap-add")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try cap_add.append(allocator, try std.fmt.parseInt(u8, argv.items[idx], 10));
            } else if (eql(arg, "--json-status-fd")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                status.json_status_fd = try std.fmt.parseInt(i32, argv.items[idx], 10);
            } else if (eql(arg, "--sync-fd")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                status.sync_fd = try std.fmt.parseInt(i32, argv.items[idx], 10);
            } else if (eql(arg, "--block-fd")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                status.block_fd = try std.fmt.parseInt(i32, argv.items[idx], 10);
            } else if (eql(arg, "--userns-block-fd")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                status.userns_block_fd = try std.fmt.parseInt(i32, argv.items[idx], 10);
            } else if (eql(arg, "--lock-file")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                status.lock_file_path = argv.items[idx];
            } else if (eql(arg, "--bind")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .bind = try parseMountPair(argv.items[idx]) });
            } else if (eql(arg, "--ro-bind")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .ro_bind = try parseMountPair(argv.items[idx]) });
            } else if (eql(arg, "--proc")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .proc = argv.items[idx] });
            } else if (eql(arg, "--dev")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .dev = argv.items[idx] });
            } else if (eql(arg, "--tmpfs")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .tmpfs = try parseTmpfs(argv.items[idx]) });
            } else if (eql(arg, "--dir")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .dir = try parseDir(argv.items[idx]) });
            } else if (eql(arg, "--symlink")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .symlink = try parseSymlink(argv.items[idx]) });
            } else if (eql(arg, "--chmod")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .chmod = try parseChmod(argv.items[idx]) });
            } else if (eql(arg, "--remount-ro")) {
                idx += 1;
                if (idx >= argv.items.len) return error.MissingValue;
                try fs_actions.append(allocator, .{ .remount_ro = argv.items[idx] });
            } else {
                return error.InvalidOption;
            }
            idx += 1;
        }

        if (idx >= argv.items.len) return error.MissingName;
        const name = argv.items[idx];
        idx += 1;

        if (idx >= argv.items.len) return error.MissingRootfs;
        const rootfs_path = argv.items[idx];
        idx += 1;

        const cmd = if (idx < argv.items.len)
            try allocator.dupe([]const u8, argv.items[idx..])
        else blk: {
            const default_cmd = try allocator.alloc([]const u8, 1);
            default_cmd[0] = "/bin/sh";
            break :blk default_cmd;
        };

        process.set_env = try set_env.toOwnedSlice(allocator);
        process.unset_env = try unset_env.toOwnedSlice(allocator);
        security.cap_drop = try cap_drop.toOwnedSlice(allocator);
        security.cap_add = try cap_add.toOwnedSlice(allocator);
        security.seccomp_filter_fds = try seccomp_fds.toOwnedSlice(allocator);
        const owned_fs_actions = try fs_actions.toOwnedSlice(allocator);

        return .{
            .resources = resources,
            .isolation = isolation,
            .process = process,
            .security = security,
            .status = status,
            .fs_actions = owned_fs_actions,
            .profile = profile,
            .name = name,
            .rootfs_path = rootfs_path,
            .cmd = cmd,
        };
    }

    fn parseProfile(value: []const u8) ?LaunchProfile {
        if (eql(value, "minimal")) return .minimal;
        if (eql(value, "default")) return .default;
        if (eql(value, "full_isolation")) return .full_isolation;
        return null;
    }

    fn parseSetEnv(value: []const u8) !EnvironmentEntry {
        const sep = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidSetEnv;
        if (sep == 0) return error.InvalidSetEnv;

        return .{
            .key = value[0..sep],
            .value = value[sep + 1 ..],
        };
    }

    fn parseSeccompMode(value: []const u8) ?SeccompMode {
        if (eql(value, "disabled")) return .disabled;
        if (eql(value, "strict")) return .strict;
        return null;
    }

    fn parseMountPair(value: []const u8) !config.MountPair {
        var parts = std.mem.splitScalar(u8, value, ':');
        const src = parts.next() orelse return error.InvalidMountPair;
        const dest = parts.next() orelse return error.InvalidMountPair;
        if (parts.next() != null) return error.InvalidMountPair;
        if (src.len == 0 or dest.len == 0) return error.InvalidMountPair;
        return .{ .src = src, .dest = dest };
    }

    fn parseTmpfs(value: []const u8) !config.TmpfsMount {
        var out = config.TmpfsMount{ .dest = value };
        var first = std.mem.splitScalar(u8, value, ':');
        out.dest = first.next() orelse return error.InvalidTmpfs;
        if (out.dest.len == 0) return error.InvalidTmpfs;

        const opts = first.next();
        if (opts == null) return out;
        if (first.next() != null) return error.InvalidTmpfs;

        var kvs = std.mem.splitScalar(u8, opts.?, ',');
        while (kvs.next()) |kv| {
            var parts = std.mem.splitScalar(u8, kv, '=');
            const key = parts.next() orelse return error.InvalidTmpfs;
            const val = parts.next() orelse return error.InvalidTmpfs;
            if (parts.next() != null) return error.InvalidTmpfs;

            if (eql(key, "size")) {
                out.size_bytes = try std.fmt.parseInt(usize, val, 10);
            } else if (eql(key, "mode")) {
                out.mode = try std.fmt.parseInt(u32, val, 8);
            } else {
                return error.InvalidTmpfs;
            }
        }

        return out;
    }

    fn parseDir(value: []const u8) !config.DirAction {
        var parts = std.mem.splitScalar(u8, value, ':');
        const path = parts.next() orelse return error.InvalidDir;
        if (path.len == 0) return error.InvalidDir;

        const mode = if (parts.next()) |m|
            try std.fmt.parseInt(u32, m, 8)
        else
            null;

        if (parts.next() != null) return error.InvalidDir;
        return .{ .path = path, .mode = mode };
    }

    fn parseSymlink(value: []const u8) !config.SymlinkAction {
        var parts = std.mem.splitScalar(u8, value, ':');
        const target = parts.next() orelse return error.InvalidSymlink;
        const path = parts.next() orelse return error.InvalidSymlink;
        if (parts.next() != null) return error.InvalidSymlink;
        if (target.len == 0 or path.len == 0) return error.InvalidSymlink;
        return .{ .target = target, .path = path };
    }

    fn parseChmod(value: []const u8) !config.ChmodAction {
        var parts = std.mem.splitScalar(u8, value, ':');
        const path = parts.next() orelse return error.InvalidChmod;
        const mode = parts.next() orelse return error.InvalidChmod;
        if (parts.next() != null) return error.InvalidChmod;
        if (path.len == 0) return error.InvalidChmod;
        return .{ .path = path, .mode = try std.fmt.parseInt(u32, mode, 8) };
    }
};

pub const Args = union(enum) {
    run: RunArgs,
    ps,
    doctor,
    help,
};

pub const help =
    \\voidbox: namespace jail launcher
    \\
    \\arguments:
    \\run [resource flags] [namespace flags] <name> <rootfs_path> [cmd ...]
    \\  resource flags: -mem <val> -cpu <val> -pids <val>
    \\  namespace flags: --no-net --no-mount --no-pid --no-uts --no-ipc
    \\  profile: --profile minimal|default|full_isolation
    \\  process flags: --chdir <path> --argv0 <value> --setenv KEY=VAL --unsetenv KEY --clearenv --new-session --die-with-parent
    \\  security flags: --no-new-privs --allow-new-privs --seccomp disabled|strict --seccomp-fd <fd> --cap-drop <num> --cap-add <num>
    \\  status flags: --json-status-fd <fd> --sync-fd <fd> --block-fd <fd> --userns-block-fd <fd> --lock-file <path>
    \\  fs flags: --bind SRC:DEST --ro-bind SRC:DEST --proc DEST --dev DEST --tmpfs DEST[:size=N,mode=OCT] --dir PATH[:MODE] --symlink TARGET:PATH --chmod PATH:MODE --remount-ro DEST
    \\  default command when omitted: /bin/sh
    \\ps
    \\doctor
    \\help
    \\
;

pub fn parseArgs(allocator: std.mem.Allocator) !Args {
    var cli_args = try std.process.argsWithAllocator(allocator);
    _ = cli_args.next(); // skip first arg
    const cmd = cli_args.next() orelse return error.InvalidArgs;

    inline for (std.meta.fields(Args)) |f| {
        if (f.type != void and !@hasDecl(f.type, "parse")) @compileError("must define parse fn");
        if (eql(cmd, f.name)) {
            if (f.type == void) {
                return @unionInit(Args, f.name, {});
            } else {
                return @unionInit(Args, f.name, try f.type.parse(allocator, &cli_args));
            }
        }
    }

    return error.InvalidArgs;
}
