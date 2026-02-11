const std = @import("std");
const linux = std.os.linux;
const voidbox = @import("voidbox");

const Parsed = struct {
    cfg: voidbox.JailConfig,
    cmd: []const []const u8,
    try_options: TryOptions,
    level_prefix: bool,
};

const TryOptions = struct {
    unshare_user_try: bool = false,
    unshare_cgroup_try: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    const parse_level_prefix = hasLevelPrefix(argv[1..]);

    const parsed = parseBwrapArgs(allocator, argv[1..]) catch |err| {
        if (err == error.HelpRequested) {
            try printUsage();
            std.posix.exit(0);
        }

        try printCliError(err, parse_level_prefix);
        try printUsage();
        std.posix.exit(2);
    };
    defer allocator.free(parsed.cmd);

    var cfg = parsed.cfg;
    var fallback_used = false;

    const outcome = launch: while (true) {
        voidbox.validate(cfg) catch |err| {
            try printWithPrefix(parsed.level_prefix, "validation failed: {s}\n", .{@errorName(err)});
            std.posix.exit(2);
        };

        const launch_result = voidbox.launch(cfg, allocator);
        if (launch_result) |ok| {
            if (!fallback_used and ok.exit_code == 127 and applyTryFallbackOnSpawnFailure(&cfg, parsed.try_options)) {
                fallback_used = true;
                continue;
            }
            break :launch ok;
        } else |err| {
            if (!fallback_used and err == error.SpawnFailed and applyTryFallbackOnSpawnFailure(&cfg, parsed.try_options)) {
                fallback_used = true;
                continue;
            }

            try printWithPrefix(parsed.level_prefix, "launch failed: {s}\n", .{@errorName(err)});
            try printWithPrefix(parsed.level_prefix, "hint: verify required namespaces/capabilities are available on this host\n", .{});
            std.posix.exit(1);
        }
    };

    std.posix.exit(outcome.exit_code);
}

fn parseBwrapArgs(allocator: std.mem.Allocator, raw: []const []const u8) !Parsed {
    const args = try expandArgsFromFd(allocator, raw, 0);
    defer allocator.free(args);

    if (args.len == 0) return error.HelpRequested;

    var cfg: voidbox.JailConfig = .{
        .name = "sandbox",
        .rootfs_path = "/",
        .cmd = &.{"/bin/sh"},
        .isolation = .{
            .user = false,
            .net = false,
            .mount = true,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
    };

    var pending_mode: ?u32 = null;
    var pending_size: ?usize = null;
    var overlay_key_index: usize = 0;
    var latest_overlay_key: ?[]const u8 = null;

    var fs_actions = std.ArrayList(voidbox.FsAction).empty;
    defer fs_actions.deinit(allocator);

    var env_set = std.ArrayList(voidbox.EnvironmentEntry).empty;
    defer env_set.deinit(allocator);

    var env_unset = std.ArrayList([]const u8).empty;
    defer env_unset.deinit(allocator);

    var cap_add = std.ArrayList(u8).empty;
    defer cap_add.deinit(allocator);

    var cap_drop = std.ArrayList(u8).empty;
    defer cap_drop.deinit(allocator);

    var seccomp_fds = std.ArrayList(i32).empty;
    defer seccomp_fds.deinit(allocator);

    var command = std.ArrayList([]const u8).empty;
    defer command.deinit(allocator);

    var i: usize = 0;
    var try_options = TryOptions{};
    var level_prefix = false;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-h")) return error.HelpRequested;

        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < args.len) : (i += 1) {
                try command.append(allocator, args[i]);
            }
            break;
        }

        if (!std.mem.startsWith(u8, arg, "--")) {
            while (i < args.len) : (i += 1) {
                try command.append(allocator, args[i]);
            }
            break;
        }

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return error.HelpRequested;
        if (std.mem.eql(u8, arg, "--version")) {
            const out = std.fs.File.stdout().deprecatedWriter();
            try out.writeAll("vb 0.0.1\n");
            std.posix.exit(0);
        }
        if (std.mem.eql(u8, arg, "--level-prefix")) {
            level_prefix = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--args")) {
            return error.ArgsAlreadyExpanded;
        }

        if (std.mem.eql(u8, arg, "--unshare-all")) {
            cfg.isolation.user = true;
            cfg.isolation.ipc = true;
            cfg.isolation.pid = true;
            cfg.isolation.net = true;
            cfg.isolation.uts = true;
            cfg.isolation.cgroup = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--share-net")) {
            cfg.isolation.net = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-user")) {
            cfg.isolation.user = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-user-try")) {
            cfg.isolation.user = true;
            try_options.unshare_user_try = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-ipc")) {
            cfg.isolation.ipc = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-pid")) {
            cfg.isolation.pid = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-net")) {
            cfg.isolation.net = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-uts")) {
            cfg.isolation.uts = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-mount")) {
            cfg.isolation.mount = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-cgroup")) {
            cfg.isolation.cgroup = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-cgroup-try")) {
            cfg.isolation.cgroup = true;
            try_options.unshare_cgroup_try = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--userns")) {
            cfg.namespace_fds.user = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--userns2")) {
            cfg.namespace_fds.user2 = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--pidns")) {
            cfg.namespace_fds.pid = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--netns")) {
            cfg.namespace_fds.net = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--mntns")) {
            cfg.namespace_fds.mount = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--utsns")) {
            cfg.namespace_fds.uts = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--ipcns")) {
            cfg.namespace_fds.ipc = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--disable-userns")) {
            cfg.security.disable_userns = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--assert-userns-disabled")) {
            cfg.security.assert_userns_disabled = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--uid")) {
            cfg.runtime.uid = @intCast(try parseFd(try nextArg(args, &i, arg)));
            continue;
        }
        if (std.mem.eql(u8, arg, "--gid")) {
            cfg.runtime.gid = @intCast(try parseFd(try nextArg(args, &i, arg)));
            continue;
        }
        if (std.mem.eql(u8, arg, "--hostname")) {
            cfg.runtime.hostname = try nextArg(args, &i, arg);
            continue;
        }

        if (std.mem.eql(u8, arg, "--argv0")) {
            cfg.process.argv0 = try nextArg(args, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--chdir")) {
            cfg.process.chdir = try nextArg(args, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--setenv")) {
            const key = try nextArg(args, &i, arg);
            const value = try nextArg(args, &i, arg);
            try env_set.append(allocator, .{ .key = key, .value = value });
            continue;
        }
        if (std.mem.eql(u8, arg, "--unsetenv")) {
            try env_unset.append(allocator, try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--clearenv")) {
            cfg.process.clear_env = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--lock-file")) {
            cfg.status.lock_file_path = try nextArg(args, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--sync-fd")) {
            cfg.status.sync_fd = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--block-fd")) {
            cfg.status.block_fd = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--userns-block-fd")) {
            cfg.status.userns_block_fd = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--info-fd")) {
            cfg.status.info_fd = try parseFd(try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--json-status-fd")) {
            cfg.status.json_status_fd = try parseFd(try nextArg(args, &i, arg));
            continue;
        }

        if (std.mem.eql(u8, arg, "--perms")) {
            pending_mode = try std.fmt.parseInt(u32, try nextArg(args, &i, arg), 8);
            continue;
        }
        if (std.mem.eql(u8, arg, "--size")) {
            pending_size = try std.fmt.parseInt(usize, try nextArg(args, &i, arg), 10);
            continue;
        }

        if (std.mem.eql(u8, arg, "--bind")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .bind = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--bind-try")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .bind_try = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dev-bind")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .dev_bind = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dev-bind-try")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .dev_bind_try = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-bind")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .ro_bind = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-bind-try")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .ro_bind_try = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--remount-ro")) {
            try fs_actions.append(allocator, .{ .remount_ro = try nextArg(args, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--proc")) {
            try fs_actions.append(allocator, .{ .proc = try nextArg(args, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dev")) {
            try fs_actions.append(allocator, .{ .dev = try nextArg(args, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--tmpfs")) {
            const dest = try nextArg(args, &i, arg);
            try maybeApplyPending(allocator, &fs_actions, &pending_mode, &pending_size);
            try fs_actions.append(allocator, .{ .tmpfs = .{ .dest = dest, .mode = pending_mode, .size_bytes = pending_size } });
            pending_mode = null;
            pending_size = null;
            continue;
        }
        if (std.mem.eql(u8, arg, "--mqueue")) {
            try fs_actions.append(allocator, .{ .mqueue = try nextArg(args, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dir")) {
            const dest = try nextArg(args, &i, arg);
            try maybeApplyPending(allocator, &fs_actions, &pending_mode, &pending_size);
            try fs_actions.append(allocator, .{ .dir = .{ .path = dest, .mode = pending_mode } });
            pending_mode = null;
            pending_size = null;
            continue;
        }
        if (std.mem.eql(u8, arg, "--file")) {
            const fd = try parseFd(try nextArg(args, &i, arg));
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .file_fd = .{ .path = dest, .fd = fd } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--bind-data")) {
            const fd = try parseFd(try nextArg(args, &i, arg));
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .bind_data_fd = .{ .dest = dest, .fd = fd } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-bind-data")) {
            const fd = try parseFd(try nextArg(args, &i, arg));
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .ro_bind_data_fd = .{ .dest = dest, .fd = fd } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--symlink")) {
            const src = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .symlink = .{ .target = src, .path = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--chmod")) {
            const mode = try std.fmt.parseInt(u32, try nextArg(args, &i, arg), 8);
            const path = try nextArg(args, &i, arg);
            try fs_actions.append(allocator, .{ .chmod = .{ .path = path, .mode = mode } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--overlay-src")) {
            const src = try nextArg(args, &i, arg);
            const key = try std.fmt.allocPrint(allocator, "ov{d}", .{overlay_key_index});
            overlay_key_index += 1;
            latest_overlay_key = key;
            try fs_actions.append(allocator, .{ .overlay_src = .{ .key = key, .path = src } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--overlay")) {
            const upper = try nextArg(args, &i, arg);
            const work = try nextArg(args, &i, arg);
            const dest = try nextArg(args, &i, arg);
            const key = latest_overlay_key orelse return error.MissingOverlaySource;
            try fs_actions.append(allocator, .{ .overlay = .{ .source_key = key, .upper = upper, .work = work, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--tmp-overlay")) {
            const dest = try nextArg(args, &i, arg);
            const key = latest_overlay_key orelse return error.MissingOverlaySource;
            try fs_actions.append(allocator, .{ .tmp_overlay = .{ .source_key = key, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-overlay")) {
            const dest = try nextArg(args, &i, arg);
            const key = latest_overlay_key orelse return error.MissingOverlaySource;
            try fs_actions.append(allocator, .{ .ro_overlay = .{ .source_key = key, .dest = dest } });
            continue;
        }

        if (std.mem.eql(u8, arg, "--seccomp")) {
            const fd = try parseFd(try nextArg(args, &i, arg));
            seccomp_fds.clearRetainingCapacity();
            try seccomp_fds.append(allocator, fd);
            continue;
        }
        if (std.mem.eql(u8, arg, "--add-seccomp-fd")) {
            const fd = try parseFd(try nextArg(args, &i, arg));
            try seccomp_fds.append(allocator, fd);
            continue;
        }
        if (std.mem.eql(u8, arg, "--exec-label")) {
            cfg.security.exec_label = try nextArg(args, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--file-label")) {
            cfg.security.file_label = try nextArg(args, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--new-session")) {
            cfg.process.new_session = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--die-with-parent")) {
            cfg.process.die_with_parent = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--as-pid-1")) {
            cfg.runtime.as_pid_1 = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--cap-add")) {
            try appendCapabilities(allocator, &cap_add, try nextArg(args, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--cap-drop")) {
            try appendCapabilities(allocator, &cap_drop, try nextArg(args, &i, arg));
            continue;
        }

        return error.UnknownOption;
    }

    cfg.process.set_env = try env_set.toOwnedSlice(allocator);
    cfg.process.unset_env = try env_unset.toOwnedSlice(allocator);
    cfg.security.cap_add = try cap_add.toOwnedSlice(allocator);
    cfg.security.cap_drop = try cap_drop.toOwnedSlice(allocator);
    cfg.security.seccomp_filter_fds = try seccomp_fds.toOwnedSlice(allocator);
    cfg.fs_actions = try fs_actions.toOwnedSlice(allocator);
    if (cfg.fs_actions.len > 0) cfg.isolation.mount = true;

    applyTryIsolationSemantics(&cfg, try_options);

    cfg.cmd = if (command.items.len == 0) &.{"/bin/sh"} else try command.toOwnedSlice(allocator);

    return .{ .cfg = cfg, .cmd = cfg.cmd, .try_options = try_options, .level_prefix = level_prefix };
}

fn hasLevelPrefix(args: []const []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--level-prefix")) return true;
    }
    return false;
}

fn applyTryFallbackOnSpawnFailure(cfg: *voidbox.JailConfig, try_options: TryOptions) bool {
    var changed = false;
    if (try_options.unshare_user_try and cfg.isolation.user) {
        cfg.isolation.user = false;
        changed = true;
    }
    if (try_options.unshare_cgroup_try and cfg.isolation.cgroup) {
        cfg.isolation.cgroup = false;
        changed = true;
    }
    return changed;
}

fn applyTryIsolationSemantics(cfg: *voidbox.JailConfig, try_options: TryOptions) void {
    if (try_options.unshare_user_try and !probeUserIsolationPath()) {
        cfg.isolation.user = false;
    }
    if (try_options.unshare_cgroup_try and !probeUnshare(linux.CLONE.NEWCGROUP)) {
        cfg.isolation.cgroup = false;
    }
}

fn probeUnshare(flag: u32) bool {
    const child_pid = std.posix.fork() catch return false;
    if (child_pid == 0) {
        const rc = linux.unshare(flag);
        const signed: isize = @bitCast(rc);
        if (signed < 0 and signed > -4096) linux.exit(1);
        linux.exit(0);
    }

    const wait_res = std.posix.waitpid(child_pid, 0);
    const status = wait_res.status;
    if ((status & 0x7f) == 0) {
        return ((status >> 8) & 0xff) == 0;
    }
    return false;
}

fn probeUserIsolationPath() bool {
    const uid = linux.getuid();
    const gid = linux.getgid();

    const child_pid = std.posix.fork() catch return false;
    if (child_pid == 0) {
        const unshare_res = linux.unshare(linux.CLONE.NEWUSER);
        const unshare_signed: isize = @bitCast(unshare_res);
        if (unshare_signed < 0 and unshare_signed > -4096) linux.exit(1);

        var uid_buf: [64]u8 = undefined;
        var gid_buf: [64]u8 = undefined;
        const uid_line = std.fmt.bufPrint(&uid_buf, "0 {} 1\n", .{uid}) catch {
            linux.exit(1);
        };
        const gid_line = std.fmt.bufPrint(&gid_buf, "0 {} 1\n", .{gid}) catch {
            linux.exit(1);
        };

        if (std.fs.openFileAbsolute("/proc/self/setgroups", .{ .mode = .write_only })) |setgroups_file| {
            defer setgroups_file.close();
            _ = setgroups_file.write("deny\n") catch {};
        } else |_| {}

        var uid_map = std.fs.openFileAbsolute("/proc/self/uid_map", .{ .mode = .write_only }) catch {
            linux.exit(1);
        };
        defer uid_map.close();
        _ = uid_map.write(uid_line) catch {
            linux.exit(1);
        };

        var gid_map = std.fs.openFileAbsolute("/proc/self/gid_map", .{ .mode = .write_only }) catch {
            linux.exit(1);
        };
        defer gid_map.close();
        _ = gid_map.write(gid_line) catch {
            linux.exit(1);
        };

        const mount_ns_res = linux.unshare(linux.CLONE.NEWNS);
        const mount_ns_signed: isize = @bitCast(mount_ns_res);
        if (mount_ns_signed < 0 and mount_ns_signed > -4096) {
            linux.exit(1);
        }

        const make_private_res = linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0);
        const make_private_signed: isize = @bitCast(make_private_res);
        if (make_private_signed < 0 and make_private_signed > -4096) {
            linux.exit(1);
        }

        linux.exit(0);
    }

    const wait_res = std.posix.waitpid(child_pid, 0);
    const status = wait_res.status;
    if ((status & 0x7f) == 0) {
        return ((status >> 8) & 0xff) == 0;
    }
    return false;
}

fn appendCapabilities(allocator: std.mem.Allocator, out: *std.ArrayList(u8), raw: []const u8) !void {
    if (std.ascii.eqlIgnoreCase(raw, "ALL")) {
        var cap: u8 = 0;
        while (cap < 64) : (cap += 1) {
            if (std.os.linux.CAP.valid(cap)) {
                try out.append(allocator, cap);
            }
        }
        return;
    }

    try out.append(allocator, try parseCapability(raw));
}

fn parseCapability(raw: []const u8) !u8 {
    return std.fmt.parseInt(u8, raw, 10) catch {
        if (std.ascii.eqlIgnoreCase(raw, "NET_RAW") or std.ascii.eqlIgnoreCase(raw, "CAP_NET_RAW")) return std.os.linux.CAP.NET_RAW;
        if (std.ascii.eqlIgnoreCase(raw, "NET_ADMIN") or std.ascii.eqlIgnoreCase(raw, "CAP_NET_ADMIN")) return std.os.linux.CAP.NET_ADMIN;
        if (std.ascii.eqlIgnoreCase(raw, "SYS_ADMIN") or std.ascii.eqlIgnoreCase(raw, "CAP_SYS_ADMIN")) return std.os.linux.CAP.SYS_ADMIN;
        if (std.ascii.eqlIgnoreCase(raw, "SETUID") or std.ascii.eqlIgnoreCase(raw, "CAP_SETUID")) return std.os.linux.CAP.SETUID;
        if (std.ascii.eqlIgnoreCase(raw, "SETGID") or std.ascii.eqlIgnoreCase(raw, "CAP_SETGID")) return std.os.linux.CAP.SETGID;
        return error.InvalidCapability;
    };
}

fn maybeApplyPending(allocator: std.mem.Allocator, actions: *std.ArrayList(voidbox.FsAction), pending_mode: *?u32, pending_size: *?usize) !void {
    if (pending_mode.*) |mode| {
        try actions.append(allocator, .{ .perms = mode });
    }
    if (pending_size.*) |size| {
        try actions.append(allocator, .{ .size = size });
    }
}

fn nextArg(args: []const []const u8, i: *usize, option: []const u8) ![]const u8 {
    if (i.* + 1 >= args.len) {
        std.debug.print("missing value for {s}\n", .{option});
        return error.MissingOptionValue;
    }
    i.* += 1;
    return args[i.*];
}

fn expandArgsFromFd(allocator: std.mem.Allocator, input: []const []const u8, depth: usize) ![]const []const u8 {
    if (depth > 8) return error.ArgsExpansionDepthExceeded;

    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const arg = input[i];
        if (std.mem.eql(u8, arg, "--args")) {
            if (i + 1 >= input.len) return error.MissingOptionValue;
            i += 1;
            const fd = try parseFd(input[i]);
            const expanded = try readArgVectorFromFd(allocator, fd);
            defer allocator.free(expanded);

            const nested = try expandArgsFromFd(allocator, expanded, depth + 1);
            defer allocator.free(nested);
            try out.appendSlice(allocator, nested);
            continue;
        }

        try out.append(allocator, arg);
    }

    return out.toOwnedSlice(allocator);
}

fn readArgVectorFromFd(allocator: std.mem.Allocator, fd: i32) ![]const []const u8 {
    var file = std.fs.File{ .handle = fd };
    const data = try file.readToEndAlloc(allocator, 1 << 20);
    defer allocator.free(data);

    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(allocator);

    var start: usize = 0;
    var idx: usize = 0;
    while (idx < data.len) : (idx += 1) {
        if (data[idx] != 0) continue;
        if (idx > start) {
            const dup = try allocator.dupe(u8, data[start..idx]);
            try out.append(allocator, dup);
        }
        start = idx + 1;
    }
    if (start < data.len) {
        const dup = try allocator.dupe(u8, data[start..]);
        try out.append(allocator, dup);
    }

    return out.toOwnedSlice(allocator);
}

fn parseFd(raw: []const u8) !i32 {
    const v = try std.fmt.parseInt(i32, raw, 10);
    if (v < 0) return error.InvalidFd;
    return v;
}

fn printCliError(err: anyerror, level_prefix: bool) !void {
    switch (err) {
        error.HelpRequested => {},
        error.UnsupportedOption => try printWithPrefix(level_prefix, "unsupported option in current voidbox backend\n", .{}),
        else => try printWithPrefix(level_prefix, "argument error: {s}\n", .{@errorName(err)}),
    }
}

fn printWithPrefix(level_prefix: bool, comptime fmt: []const u8, args: anytype) !void {
    if (level_prefix) {
        std.debug.print("vb: ", .{});
    }
    std.debug.print(fmt, args);
}

fn printUsage() !void {
    const out = std.fs.File.stdout().deprecatedWriter();

    const color = shouldUseColor();
    const reset = if (color) "\x1b[0m" else "";
    const title = if (color) "\x1b[96m" else "";
    const section = if (color) "\x1b[94m" else "";
    const option = if (color) "\x1b[93m" else "";
    const dim = if (color) "\x1b[37m" else "";

    try out.print("{s}voidbox cli{s}\n", .{ title, reset });
    try out.print("{s}usage{s}  vb [OPTION...] [--] COMMAND [ARG...]\n\n", .{ section, reset });

    try out.print("{s}General{s}\n", .{ section, reset });
    try out.print("  {s}--help{s}                   Show this help\n", .{ option, reset });
    try out.print("  {s}--version{s}                Print version\n", .{ option, reset });
    try out.print("  {s}--args{s} FD                Parse NUL-separated args from FD\n", .{ option, reset });
    try out.print("  {s}--level-prefix{s}           Prefix diagnostics with 'vb:'\n\n", .{ option, reset });

    try out.print("{s}Namespaces{s}\n", .{ section, reset });
    try out.print("  {s}--unshare-user{s} | {s}--unshare-user-try{s}\n", .{ option, reset, option, reset });
    try out.print("  {s}--unshare-ipc{s} | {s}--unshare-pid{s} | {s}--unshare-net{s} | {s}--share-net{s}\n", .{ option, reset, option, reset, option, reset, option, reset });
    try out.print("  {s}--unshare-uts{s} | {s}--unshare-cgroup{s} | {s}--unshare-cgroup-try{s}\n", .{ option, reset, option, reset, option, reset });
    try out.print("  {s}--unshare-all{s}\n", .{ option, reset });
    try out.print("  {s}--userns{s} FD | {s}--userns2{s} FD | {s}--pidns{s} FD\n", .{ option, reset, option, reset, option, reset });
    try out.print("  {s}--netns{s} FD | {s}--mntns{s} FD | {s}--utsns{s} FD | {s}--ipcns{s} FD\n", .{ option, reset, option, reset, option, reset, option, reset });
    try out.print("  {s}--uid{s} UID | {s}--gid{s} GID | {s}--hostname{s} HOST\n\n", .{ option, reset, option, reset, option, reset });

    try out.print("{s}Process And Env{s}\n", .{ section, reset });
    try out.print("  {s}--chdir{s} DIR\n", .{ option, reset });
    try out.print("  {s}--setenv{s} VAR VALUE     (repeatable)\n", .{ option, reset });
    try out.print("  {s}--unsetenv{s} VAR         (repeatable)\n", .{ option, reset });
    try out.print("  {s}--clearenv{s}\n", .{ option, reset });
    try out.print("  {s}--argv0{s} VALUE\n", .{ option, reset });
    try out.print("  {s}--new-session{s} | {s}--die-with-parent{s} | {s}--as-pid-1{s}\n\n", .{ option, reset, option, reset, option, reset });

    try out.print("{s}Status And Security{s}\n", .{ section, reset });
    try out.print("  {s}--lock-file{s} PATH\n", .{ option, reset });
    try out.print("  {s}--sync-fd{s} FD | {s}--block-fd{s} FD | {s}--userns-block-fd{s} FD\n", .{ option, reset, option, reset, option, reset });
    try out.print("  {s}--info-fd{s} FD | {s}--json-status-fd{s} FD\n", .{ option, reset, option, reset });
    try out.print("  {s}--seccomp{s} FD | {s}--add-seccomp-fd{s} FD\n", .{ option, reset, option, reset });
    try out.print("  {s}--cap-add{s} CAP | {s}--cap-drop{s} CAP\n", .{ option, reset, option, reset });
    try out.print("  {s}--exec-label{s} LABEL | {s}--file-label{s} LABEL\n", .{ option, reset, option, reset });
    try out.print("  {s}--disable-userns{s} | {s}--assert-userns-disabled{s}\n\n", .{ option, reset, option, reset });

    try out.print("{s}Filesystem{s}\n", .{ section, reset });
    try out.print("  {s}--perms{s} OCTAL | {s}--size{s} BYTES\n", .{ option, reset, option, reset });
    try out.print("  {s}--bind{s} SRC DEST | {s}--bind-try{s} SRC DEST\n", .{ option, reset, option, reset });
    try out.print("  {s}--dev-bind{s} SRC DEST | {s}--dev-bind-try{s} SRC DEST\n", .{ option, reset, option, reset });
    try out.print("  {s}--ro-bind{s} SRC DEST | {s}--ro-bind-try{s} SRC DEST | {s}--remount-ro{s} DEST\n", .{ option, reset, option, reset, option, reset });
    try out.print("  {s}--proc{s} DEST | {s}--dev{s} DEST | {s}--tmpfs{s} DEST | {s}--mqueue{s} DEST | {s}--dir{s} DEST\n", .{ option, reset, option, reset, option, reset, option, reset, option, reset });
    try out.print("  {s}--file{s} FD DEST | {s}--bind-data{s} FD DEST | {s}--ro-bind-data{s} FD DEST\n", .{ option, reset, option, reset, option, reset });
    try out.print("  {s}--symlink{s} SRC DEST | {s}--chmod{s} OCTAL PATH\n", .{ option, reset, option, reset });
    try out.print("  {s}--overlay-src{s} SRC | {s}--overlay{s} RWSRC WORKDIR DEST\n", .{ option, reset, option, reset });
    try out.print("  {s}--tmp-overlay{s} DEST | {s}--ro-overlay{s} DEST\n\n", .{ option, reset, option, reset });

    try out.print("{s}Examples{s}\n", .{ section, reset });
    try out.print("  {s}vb --unshare-user --proc /proc --dev /dev -- /bin/sh{s}\n", .{ dim, reset });
    try out.print("  {s}vb --ro-bind /usr /usr --tmpfs /tmp -- /usr/bin/env{s}\n\n", .{ dim, reset });
}

fn shouldUseColor() bool {
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "NO_COLOR")) |v| {
        defer std.heap.page_allocator.free(v);
        return false;
    } else |_| {}

    if (std.process.getEnvVarOwned(std.heap.page_allocator, "CLICOLOR")) |v| {
        defer std.heap.page_allocator.free(v);
        if (v.len == 1 and v[0] == '0') return false;
    } else |_| {}

    return std.posix.isatty(std.posix.STDOUT_FILENO);
}

test "expandArgsFromFd expands NUL-separated args" {
    const allocator = std.heap.page_allocator;
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);

    const payload = "--help\x00";
    _ = try std.posix.write(pipefds[1], payload);
    std.posix.close(pipefds[1]);

    var fd_buf: [16]u8 = undefined;
    const fd_arg = try std.fmt.bufPrint(&fd_buf, "{d}", .{pipefds[0]});

    const expanded = try expandArgsFromFd(allocator, &.{ "--args", fd_arg }, 0);
    defer allocator.free(expanded);

    try std.testing.expectEqual(@as(usize, 1), expanded.len);
    try std.testing.expectEqualStrings("--help", expanded[0]);
}

test "parseBwrapArgs parses namespace fd options" {
    const allocator = std.testing.allocator;
    const parsed = try parseBwrapArgs(allocator, &.{
        "--netns", "10",
        "--mntns", "11",
        "--utsns", "12",
        "--ipcns", "13",
        "--",      "/bin/true",
    });
    defer allocator.free(parsed.cmd);

    try std.testing.expectEqual(@as(?i32, 10), parsed.cfg.namespace_fds.net);
    try std.testing.expectEqual(@as(?i32, 11), parsed.cfg.namespace_fds.mount);
    try std.testing.expectEqual(@as(?i32, 12), parsed.cfg.namespace_fds.uts);
    try std.testing.expectEqual(@as(?i32, 13), parsed.cfg.namespace_fds.ipc);
}
