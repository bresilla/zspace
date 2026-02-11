const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const FsAction = @import("config.zig").FsAction;
const OverlaySource = @import("config.zig").OverlaySource;
const TmpfsMount = @import("config.zig").TmpfsMount;

const MountedTarget = struct {
    path: []const u8,
};

pub fn execute(actions: []const FsAction) !void {
    var overlay_sources = std.ArrayList(OverlaySource).empty;
    defer overlay_sources.deinit(std.heap.page_allocator);
    var tmp_overlay_counter: usize = 0;
    var data_bind_counter: usize = 0;
    var current_mode: ?u32 = null;
    var current_size: ?usize = null;
    var mounted_targets = std.ArrayList(MountedTarget).empty;
    defer mounted_targets.deinit(std.heap.page_allocator);
    errdefer rollbackMounts(mounted_targets.items);

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

                const overlay_base = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.voidbox-overlay/{s}-{d}", .{ o.source_key, tmp_overlay_counter });
                defer std.heap.page_allocator.free(overlay_base);
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
                const src = try writeDataSource(b.data, data_bind_counter);
                defer std.heap.page_allocator.free(src);

                try ensurePath(b.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                data_bind_counter += 1;
            },
            .ro_bind_data => |b| {
                const src = try writeDataSource(b.data, data_bind_counter);
                defer std.heap.page_allocator.free(src);

                try ensurePath(b.dest);
                const bind_flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });

                const remount_flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, b.dest, null, remount_flags, null, error.RemountReadOnly);
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
                const src = try writeDataSourceFromFd(b.fd, data_bind_counter);
                defer std.heap.page_allocator.free(src);

                try ensurePath(b.dest);
                const flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                data_bind_counter += 1;
            },
            .ro_bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(b.fd, data_bind_counter);
                defer std.heap.page_allocator.free(src);

                try ensurePath(b.dest);
                const bind_flags = linux.MS.BIND | linux.MS.REC;
                try mountPath(src, b.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });

                const remount_flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY;
                try mountPath(null, b.dest, null, remount_flags, null, error.RemountReadOnly);
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

fn writeDataSource(data: []const u8, index: usize) ![]const u8 {
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.voidbox-data/{d}", .{index});
    const parent = std.fs.path.dirname(path);
    if (parent) |p| {
        try ensurePath(p);
    }

    var file = try std.fs.cwd().createFile(trimPath(path), .{ .truncate = true });
    defer file.close();
    try file.writeAll(data);
    return path;
}

fn writeDataSourceFromFd(fd: i32, index: usize) ![]const u8 {
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.voidbox-data/{d}", .{index});
    const parent = std.fs.path.dirname(path);
    if (parent) |p| {
        try ensurePath(p);
    }

    var out_file = try std.fs.cwd().createFile(trimPath(path), .{ .truncate = true });
    defer out_file.close();
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

    try checkErr(linux.mount(special_ptr, &dir_z, fstype_ptr, flags, if (data_ptr) |p| @intFromPtr(p) else 0), err_ty);
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
