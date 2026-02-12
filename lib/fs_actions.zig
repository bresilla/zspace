const std = @import("std");
const linux = std.os.linux;
const checkErrAllowBusy = @import("utils.zig").checkErrAllowBusy;
const FsAction = @import("config.zig").FsAction;
const OverlaySource = @import("config.zig").OverlaySource;
const TmpfsMount = @import("config.zig").TmpfsMount;

const MountedTarget = struct {
    path: []const u8,
};

pub fn execute(instance_id: []const u8, actions: []const FsAction) !void {
    var overlay_sources = std.ArrayList(OverlaySource).empty;
    defer overlay_sources.deinit(std.heap.page_allocator);
    var tmp_overlay_counter: usize = 0;
    var data_bind_counter: usize = 0;
    var current_mode: ?u32 = null;
    var current_size: ?usize = null;
    var mounted_targets = std.ArrayList(MountedTarget).empty;
    defer mounted_targets.deinit(std.heap.page_allocator);

    var temp_files = std.ArrayList([]const u8).empty;
    defer {
        for (temp_files.items) |p| {
            std.heap.page_allocator.free(p);
        }
        temp_files.deinit(std.heap.page_allocator);
    }

    var temp_dirs = std.ArrayList([]const u8).empty;
    defer {
        for (temp_dirs.items) |p| {
            std.heap.page_allocator.free(p);
        }
        temp_dirs.deinit(std.heap.page_allocator);
    }

    errdefer rollbackMounts(mounted_targets.items);
    errdefer cleanupTempFiles(temp_files.items);
    errdefer cleanupTempDirs(temp_dirs.items);

    for (actions) |action| {
        switch (action) {
            .perms => |mode| {
                current_mode = mode;
            },
            .size => |size_bytes| {
                current_size = size_bytes;
            },
            .bind => |mount_pair| {
                try ensurePath(mount_pair.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .bind_try => |mount_pair| {
                if (!sourceExists(mount_pair.src)) continue;
                try ensurePath(mount_pair.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .dev_bind => |mount_pair| {
                try ensurePath(mount_pair.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .dev_bind_try => |mount_pair| {
                if (!sourceExists(mount_pair.src)) continue;
                try ensurePath(mount_pair.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .ro_bind => |mount_pair| {
                try ensurePath(mount_pair.dest);
                const bind_flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(mount_pair.src, mount_pair.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });

                const remount_flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, mount_pair.dest, null, remount_flags, null, error.RemountReadOnly);
            },
            .ro_bind_try => |mount_pair| {
                if (!sourceExists(mount_pair.src)) continue;
                try ensurePath(mount_pair.dest);
                const bind_flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(mount_pair.src, mount_pair.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });

                const remount_flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, mount_pair.dest, null, remount_flags, null, error.RemountReadOnly);
            },
            .proc => |dest| {
                if (std.mem.eql(u8, dest, "/proc")) {
                    continue;
                }
                try ensurePath(dest);
                mountPath("proc", dest, "proc", 0, null, error.MountProc) catch |err| {
                    if (err != error.MountProc) return err;
                    const flags = linux.MS.BIND | linux.MS.REC;
                    try mountPath("/proc", dest, null, flags, null, error.BindMount);
                };
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .dev => |dest| {
                try ensurePath(dest);
                mountPath("devtmpfs", dest, "devtmpfs", 0, null, error.MountDevTmpFs) catch |err| {
                    if (err != error.MountDevTmpFs) return err;
                    const flags = linux.MS.BIND | linux.MS.REC;
                    try mountPath("/dev", dest, null, flags, null, error.BindMount);
                };
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .mqueue => |dest| {
                try ensurePath(dest);
                try mountPath("mqueue", dest, "mqueue", 0, null, error.MountMqueue);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .tmpfs => |tmpfs| {
                try ensurePath(tmpfs.dest);

                const eff_tmpfs = effectiveTmpfs(tmpfs, current_size, current_mode);
                if (tmpfs.size_bytes == null and eff_tmpfs.size_bytes != null) {
                    current_size = null;
                }
                if (tmpfs.mode == null and eff_tmpfs.mode != null) {
                    current_mode = null;
                }

                var opts_buf: [64]u8 = undefined;
                const opts = if (eff_tmpfs.size_bytes != null or eff_tmpfs.mode != null)
                    try formatTmpfsOpts(&opts_buf, eff_tmpfs)
                else
                    null;

                try mountPath("tmpfs", eff_tmpfs.dest, "tmpfs", 0, opts, error.MountTmpFs);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = eff_tmpfs.dest });
            },
            .dir => |dir_action| {
                try ensurePath(dir_action.path);
                const mode = dir_action.mode orelse takeMode(&current_mode);
                if (mode) |m| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, dir_action.path, @intCast(m), 0);
                }
            },
            .symlink => |symlink| {
                const parent = std.fs.path.dirname(symlink.path);
                if (parent) |p| {
                    try ensurePath(p);
                }
                std.fs.cwd().symLink(symlink.target, trimPath(symlink.path), .{}) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
            },
            .chmod => |chmod_action| {
                try std.posix.fchmodat(std.posix.AT.FDCWD, chmod_action.path, @intCast(chmod_action.mode), 0);
            },
            .remount_ro => |dest| {
                const flags = linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, dest, null, flags, null, error.RemountReadOnly);
            },
            .overlay_src => |src| {
                try overlay_sources.append(std.heap.page_allocator, src);
            },
            .overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                try ensurePath(o.dest);
                try ensurePath(o.upper);
                try ensurePath(o.work);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s},upperdir={s},workdir={s}", .{ lower, o.upper, o.work });
                try mountPath("overlay", o.dest, "overlay", 0, opts, error.MountOverlay);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = o.dest });
            },
            .tmp_overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                try ensurePath(o.dest);

                const overlay_base = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.voidbox-overlay/{s}/{s}-{d}", .{ instance_id, o.source_key, tmp_overlay_counter });
                defer std.heap.page_allocator.free(overlay_base);
                try temp_dirs.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, overlay_base));
                const upper = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/upper", .{overlay_base});
                defer std.heap.page_allocator.free(upper);
                const work = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/work", .{overlay_base});
                defer std.heap.page_allocator.free(work);

                try ensurePath(upper);
                try ensurePath(work);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s},upperdir={s},workdir={s}", .{ lower, upper, work });
                try mountPath("overlay", o.dest, "overlay", 0, opts, error.MountOverlay);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = o.dest });
                tmp_overlay_counter += 1;
            },
            .ro_overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                try ensurePath(o.dest);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s}", .{lower});
                try mountPath("overlay", o.dest, "overlay", linux.MS.RDONLY, opts, error.MountOverlay);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = o.dest });
            },
            .bind_data => |b| {
                const src = try writeDataSource(instance_id, b.data, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .ro_bind_data => |b| {
                const src = try writeDataSource(instance_id, b.data, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const bind_flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });

                const remount_flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, b.dest, null, remount_flags, null, error.RemountReadOnly);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .file => |f| {
                const parent = std.fs.path.dirname(f.path);
                if (parent) |p| {
                    try ensurePath(p);
                }

                var file = try std.fs.cwd().createFile(trimPath(f.path), .{ .truncate = true });
                defer file.close();
                try file.writeAll(f.data);
                if (takeMode(&current_mode)) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, f.path, @intCast(mode), 0);
                }
            },
            .bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(instance_id, b.fd, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .ro_bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(instance_id, b.fd, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const bind_flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });

                const remount_flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, b.dest, null, remount_flags, null, error.RemountReadOnly);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .file_fd => |f| {
                const parent = std.fs.path.dirname(f.path);
                if (parent) |p| {
                    try ensurePath(p);
                }

                var out_file = try std.fs.cwd().createFile(trimPath(f.path), .{ .truncate = true });
                defer out_file.close();

                var in_file = std.fs.File{ .handle = f.fd };
                var buf: [4096]u8 = undefined;
                while (true) {
                    const n = try in_file.read(&buf);
                    if (n == 0) break;
                    try out_file.writeAll(buf[0..n]);
                }

                if (takeMode(&current_mode)) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, f.path, @intCast(mode), 0);
                }
            },
        }
    }
}

fn takeMode(mode_ptr: *?u32) ?u32 {
    const v = mode_ptr.*;
    mode_ptr.* = null;
    return v;
}

fn effectiveTmpfs(tmpfs: TmpfsMount, size_fallback: ?usize, mode_fallback: ?u32) TmpfsMount {
    return .{
        .dest = tmpfs.dest,
        .size_bytes = tmpfs.size_bytes orelse size_fallback,
        .mode = tmpfs.mode orelse mode_fallback,
    };
}

fn rollbackMounts(mounted_targets: []const MountedTarget) void {
    var i = mounted_targets.len;
    while (i > 0) {
        i -= 1;
        var path_z = std.posix.toPosixPath(mounted_targets[i].path) catch continue;
        _ = linux.umount2(&path_z, linux.MNT.DETACH);
    }
}

fn cleanupTempFiles(paths: []const []const u8) void {
    for (paths) |p| {
        std.fs.deleteFileAbsolute(p) catch {};
    }
}

fn cleanupTempDirs(paths: []const []const u8) void {
    var i = paths.len;
    while (i > 0) {
        i -= 1;
        std.fs.deleteTreeAbsolute(paths[i]) catch {};
    }
}

pub fn cleanupInstanceArtifacts(rootfs: []const u8, instance_id: []const u8) void {
    const data_path = rootedPath(std.heap.page_allocator, rootfs, "/tmp/.voidbox-data", instance_id) catch return;
    cleanupTree(data_path);

    const overlay_path = rootedPath(std.heap.page_allocator, rootfs, "/tmp/.voidbox-overlay", instance_id) catch return;
    cleanupTree(overlay_path);
}

fn cleanupTree(path: []u8) void {
    defer std.heap.page_allocator.free(path);
    std.fs.deleteTreeAbsolute(path) catch {};
}

fn rootedPath(allocator: std.mem.Allocator, rootfs: []const u8, base: []const u8, child: []const u8) ![]u8 {
    if (std.mem.eql(u8, rootfs, "/")) {
        return std.fs.path.join(allocator, &.{ base, child });
    }
    return std.fs.path.join(allocator, &.{ rootfs, trimPath(base), child });
}

fn writeDataSource(instance_id: []const u8, data: []const u8, index: usize) ![]const u8 {
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.voidbox-data/{s}/{d}", .{ instance_id, index });
    errdefer std.heap.page_allocator.free(path);
    const parent = std.fs.path.dirname(path);
    if (parent) |p| {
        try ensurePath(p);
    }

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    errdefer std.fs.deleteFileAbsolute(path) catch {};
    try file.writeAll(data);
    return path;
}

fn writeDataSourceFromFd(instance_id: []const u8, fd: i32, index: usize) ![]const u8 {
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.voidbox-data/{s}/{d}", .{ instance_id, index });
    errdefer std.heap.page_allocator.free(path);
    const parent = std.fs.path.dirname(path);
    if (parent) |p| {
        try ensurePath(p);
    }

    var out_file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer out_file.close();
    errdefer std.fs.deleteFileAbsolute(path) catch {};
    var in_file = std.fs.File{ .handle = fd };

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try in_file.read(&buf);
        if (n == 0) break;
        try out_file.writeAll(buf[0..n]);
    }
    return path;
}

fn findOverlaySource(sources: []const OverlaySource, key: []const u8) ?[]const u8 {
    for (sources) |src| {
        if (std.mem.eql(u8, src.key, key)) return src.path;
    }
    return null;
}

fn sourceExists(path: []const u8) bool {
    std.posix.access(path, std.posix.F_OK) catch return false;
    return true;
}

fn formatTmpfsOpts(buffer: []u8, tmpfs: @import("config.zig").TmpfsMount) ![]const u8 {
    if (tmpfs.size_bytes) |size| {
        if (tmpfs.mode) |mode| {
            return std.fmt.bufPrint(buffer, "size={},mode={o}", .{ size, mode });
        }
        return std.fmt.bufPrint(buffer, "size={}", .{size});
    }

    return std.fmt.bufPrint(buffer, "mode={o}", .{tmpfs.mode.?});
}

fn ensurePath(path: []const u8) !void {
    const normalized = trimPath(path);
    if (normalized.len == 0) return;

    if (std.mem.startsWith(u8, path, "/")) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        try root.makePath(normalized);
        return;
    }

    try std.fs.cwd().makePath(normalized);
}

fn trimPath(path: []const u8) []const u8 {
    return std.mem.trimLeft(u8, path, "/");
}

fn mountPath(
    special: ?[]const u8,
    dir: []const u8,
    fstype: ?[]const u8,
    flags: u32,
    data: ?[]const u8,
    err_ty: anytype,
) !void {
    var dir_z = try std.posix.toPosixPath(dir);

    var special_z: [std.posix.PATH_MAX - 1:0]u8 = undefined;
    const special_ptr = if (special) |s| blk: {
        special_z = try std.posix.toPosixPath(s);
        break :blk @as([*:0]const u8, &special_z);
    } else null;

    var fstype_z: [std.posix.PATH_MAX - 1:0]u8 = undefined;
    const fstype_ptr = if (fstype) |s| blk: {
        fstype_z = try std.posix.toPosixPath(s);
        break :blk @as([*:0]const u8, &fstype_z);
    } else null;

    var data_z: [std.posix.PATH_MAX - 1:0]u8 = undefined;
    const data_ptr = if (data) |d| blk: {
        data_z = try std.posix.toPosixPath(d);
        break :blk @as([*:0]const u8, &data_z);
    } else null;

    try checkErrAllowBusy(linux.mount(special_ptr, &dir_z, fstype_ptr, flags, if (data_ptr) |p| @intFromPtr(p) else 0), err_ty);
}

test "trimPath strips leading slashes" {
    try std.testing.expectEqualStrings("tmp/a", trimPath("/tmp/a"));
    try std.testing.expectEqualStrings("tmp/a", trimPath("////tmp/a"));
    try std.testing.expectEqualStrings("", trimPath("/"));
}

test "formatTmpfsOpts formats size and mode" {
    var buf: [64]u8 = undefined;
    const opts = try formatTmpfsOpts(&buf, .{ .dest = "/tmp", .size_bytes = 1024, .mode = 0o700 });
    try std.testing.expectEqualStrings("size=1024,mode=700", opts);
}

test "findOverlaySource resolves source by key" {
    const sources = [_]OverlaySource{
        .{ .key = "base", .path = "/layers/base" },
        .{ .key = "dev", .path = "/layers/dev" },
    };

    try std.testing.expectEqualStrings("/layers/dev", findOverlaySource(&sources, "dev").?);
    try std.testing.expect(findOverlaySource(&sources, "none") == null);
}

test "sourceExists handles existing and missing paths" {
    try std.testing.expect(sourceExists("/"));
    try std.testing.expect(!sourceExists("/definitely/not/a/real/path"));
}

test "ensurePath creates absolute directories" {
    const path = "/tmp/voidbox-ensure-path-abs-test/a/b";
    std.fs.deleteTreeAbsolute("/tmp/voidbox-ensure-path-abs-test") catch {};
    defer std.fs.deleteTreeAbsolute("/tmp/voidbox-ensure-path-abs-test") catch {};

    try ensurePath(path);
    try std.testing.expect(sourceExists(path));
}

test "effectiveTmpfs applies size and mode modifiers" {
    const resolved = effectiveTmpfs(.{ .dest = "/tmp" }, 2048, 0o755);
    try std.testing.expectEqual(@as(?usize, 2048), resolved.size_bytes);
    try std.testing.expectEqual(@as(?u32, 0o755), resolved.mode);

    const explicit = effectiveTmpfs(.{ .dest = "/tmp", .size_bytes = 4096, .mode = 0o700 }, 2048, 0o755);
    try std.testing.expectEqual(@as(?usize, 4096), explicit.size_bytes);
    try std.testing.expectEqual(@as(?u32, 0o700), explicit.mode);
}

test "takeMode is one-shot" {
    var mode: ?u32 = 0o755;
    try std.testing.expectEqual(@as(?u32, 0o755), takeMode(&mode));
    try std.testing.expectEqual(@as(?u32, null), takeMode(&mode));
}

test "bind_try skips missing source without failing" {
    const actions = [_]FsAction{
        .{ .bind_try = .{ .src = "/definitely/not/a/real/path", .dest = "/tmp/voidbox-bind-try-skip" } },
    };

    try execute("itest", &actions);
}

test "dev_bind_try skips missing source without failing" {
    const actions = [_]FsAction{
        .{ .dev_bind_try = .{ .src = "/definitely/not/a/real/path", .dest = "/tmp/voidbox-dev-bind-try-skip" } },
    };

    try execute("itest", &actions);
}

test "ro_bind_try skips missing source without failing" {
    const actions = [_]FsAction{
        .{ .ro_bind_try = .{ .src = "/definitely/not/a/real/path", .dest = "/tmp/voidbox-ro-bind-try-skip" } },
    };

    try execute("itest", &actions);
}

test "rootedPath maps chroot paths to host paths" {
    const p1 = try rootedPath(std.testing.allocator, "/", "/tmp/.voidbox-data", "abc");
    defer std.testing.allocator.free(p1);
    try std.testing.expectEqualStrings("/tmp/.voidbox-data/abc", p1);

    const p2 = try rootedPath(std.testing.allocator, "/srv/rootfs", "/tmp/.voidbox-overlay", "xyz");
    defer std.testing.allocator.free(p2);
    try std.testing.expectEqualStrings("/srv/rootfs/tmp/.voidbox-overlay/xyz", p2);
}

test "cleanupInstanceArtifacts removes data and overlay trees" {
    const instance_id = "itest-cleanup-artifacts";

    const data_dir = try std.fmt.allocPrint(std.testing.allocator, "/tmp/.voidbox-data/{s}", .{instance_id});
    defer std.testing.allocator.free(data_dir);
    const overlay_dir = try std.fmt.allocPrint(std.testing.allocator, "/tmp/.voidbox-overlay/{s}", .{instance_id});
    defer std.testing.allocator.free(overlay_dir);

    std.fs.deleteTreeAbsolute(data_dir) catch {};
    std.fs.deleteTreeAbsolute(overlay_dir) catch {};
    try ensurePath(data_dir);
    try ensurePath(overlay_dir);

    cleanupInstanceArtifacts("/", instance_id);

    try std.testing.expect(!sourceExists(data_dir));
    try std.testing.expect(!sourceExists(overlay_dir));
}

test "cleanup helpers remove temporary files and directories" {
    const file_path = "/tmp/voidbox-cleanup-helper-file";
    const dir_path = "/tmp/voidbox-cleanup-helper-dir";

    std.fs.deleteFileAbsolute(file_path) catch {};
    std.fs.deleteTreeAbsolute(dir_path) catch {};

    {
        var file = try std.fs.createFileAbsolute(file_path, .{ .truncate = true });
        file.close();
    }
    try ensurePath(dir_path);

    cleanupTempFiles(&.{file_path});
    cleanupTempDirs(&.{dir_path});

    try std.testing.expect(!sourceExists(file_path));
    try std.testing.expect(!sourceExists(dir_path));
}

test "execute cleans bind-data temp file on mount failure" {
    const instance_id = "itest-bind-data-rollback";
    const temp_source = "/tmp/.voidbox-data/itest-bind-data-rollback/0";

    std.fs.deleteFileAbsolute(temp_source) catch {};

    const actions = [_]FsAction{
        .{ .bind_data = .{ .data = "hello", .dest = "/tmp/voidbox-bind-data-fail" } },
    };

    try std.testing.expectError(error.BindMount, execute(instance_id, &actions));
    try std.testing.expect(!sourceExists(temp_source));
    cleanupInstanceArtifacts("/", instance_id);
}

test "execute cleans tmp-overlay temp dirs on overlay mount failure" {
    const instance_id = "itest-tmp-overlay-rollback";
    const overlay_base = "/tmp/.voidbox-overlay/itest-tmp-overlay-rollback/base-0";

    std.fs.deleteTreeAbsolute(overlay_base) catch {};

    const actions = [_]FsAction{
        .{ .overlay_src = .{ .key = "base", .path = "/definitely/not/a/real/lowerdir" } },
        .{ .tmp_overlay = .{ .source_key = "base", .dest = "/tmp/voidbox-overlay-fail" } },
    };

    try std.testing.expectError(error.MountOverlay, execute(instance_id, &actions));
    try std.testing.expect(!sourceExists(overlay_base));
    cleanupInstanceArtifacts("/", instance_id);
}

test "writeDataSourceFromFd cleans temporary file on read failure" {
    const instance_id = "itest-write-fd-cleanup";
    const leaked_path = try std.fmt.allocPrint(std.testing.allocator, "/tmp/.voidbox-data/{s}/{d}", .{ instance_id, 0 });
    defer std.testing.allocator.free(leaked_path);

    std.fs.deleteFileAbsolute(leaked_path) catch {};

    _ = writeDataSourceFromFd(instance_id, -1, 0) catch {};
    try std.testing.expect(!sourceExists(leaked_path));
    cleanupInstanceArtifacts("/", instance_id);
}
