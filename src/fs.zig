const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const FsAction = @import("config.zig").FsAction;
const OverlaySource = @import("config.zig").OverlaySource;

const MountedTarget = struct {
    path: []const u8,
};

rootfs: []const u8,
actions: []const FsAction,

const Fs = @This();

pub fn init(rootfs: []const u8, actions: []const FsAction) Fs {
    return .{ .rootfs = rootfs, .actions = actions };
}

pub fn setup(self: *Fs, mount_fs: bool) !void {
    try checkErr(linux.chroot(@ptrCast(self.rootfs)), error.Chroot);
    try checkErr(linux.chdir("/"), error.Chdir);

    if (!mount_fs) return;

    if (self.actions.len == 0) {
        try self.setupDefaultMounts();
        return;
    }

    try self.executeActions();
}

fn setupDefaultMounts(self: *Fs) !void {
    _ = self;

    try checkErr(linux.mount("proc", "proc", "proc", 0, 0), error.MountProc);
    try checkErr(linux.mount("tmpfs", "tmp", "tmpfs", 0, 0), error.MountTmpFs);
    _ = linux.mount("sysfs", "sys", "sysfs", 0, 0);
}

fn executeActions(self: *Fs) !void {
    var overlay_sources = std.ArrayList(OverlaySource).empty;
    defer overlay_sources.deinit(std.heap.page_allocator);
    var tmp_overlay_counter: usize = 0;
    var data_bind_counter: usize = 0;
    var mounted_targets = std.ArrayList(MountedTarget).empty;
    defer mounted_targets.deinit(std.heap.page_allocator);
    errdefer rollbackMounts(mounted_targets.items);

    for (self.actions) |action| {
        switch (action) {
            .bind => |mount_pair| {
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
            .proc => |dest| {
                try ensurePath(dest);
                try mountPath("proc", dest, "proc", 0, null, error.MountProc);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .dev => |dest| {
                try ensurePath(dest);
                try mountPath("devtmpfs", dest, "devtmpfs", 0, null, error.MountDevTmpFs);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .tmpfs => |tmpfs| {
                try ensurePath(tmpfs.dest);

                var opts_buf: [64]u8 = undefined;
                const opts = if (tmpfs.size_bytes != null or tmpfs.mode != null)
                    try formatTmpfsOpts(&opts_buf, tmpfs)
                else
                    null;

                try mountPath("tmpfs", tmpfs.dest, "tmpfs", 0, opts, error.MountTmpFs);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = tmpfs.dest });
            },
            .dir => |dir_action| {
                try ensurePath(dir_action.path);
                if (dir_action.mode) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, dir_action.path, @intCast(mode), 0);
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
            },
        }
    }
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

fn findOverlaySource(sources: []const OverlaySource, key: []const u8) ?[]const u8 {
    for (sources) |src| {
        if (std.mem.eql(u8, src.key, key)) return src.path;
    }
    return null;
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
