const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport(@cInclude("signal.h"));

const namespace = @import("namespace.zig");
const namespace_sequence = @import("namespace_sequence.zig");
const caps = @import("caps.zig");
const seccomp = @import("seccomp.zig");
const ProcessOptions = @import("config.zig").ProcessOptions;
const SecurityOptions = @import("config.zig").SecurityOptions;
const NamespaceFds = @import("config.zig").NamespaceFds;

pub fn prepare(
    allocator: std.mem.Allocator,
    uid: linux.uid_t,
    gid: linux.gid_t,
    process: ProcessOptions,
    security: SecurityOptions,
    namespace_fds: NamespaceFds,
) !void {
    if (linux.getgid() != gid) {
        try checkErr(linux.setregid(gid, gid), error.GID);
    }
    if (linux.getuid() != uid) {
        try checkErr(linux.setreuid(uid, uid), error.UID);
    }

    try namespace_sequence.attachInitial(namespace_fds);

    if (security.disable_userns or security.assert_userns_disabled) {
        try namespace.assertUserNsDisabled();
    }

    if (process.new_session and !std.posix.isatty(std.posix.STDIN_FILENO)) {
        _ = std.posix.setsid() catch return error.SetSidFailed;
    }
    if (process.die_with_parent) {
        try checkErr(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @as(usize, @intCast(c.SIGKILL)), 0, 0, 0), error.PrctlFailed);
    }
    if (security.no_new_privs) {
        try checkErr(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), error.NoNewPrivsFailed);
    }

    try caps.apply(security);
    try seccomp.apply(security, allocator);
}

pub fn finalizeNamespaces(namespace_fds: NamespaceFds) !void {
    try namespace_sequence.attachUserNs2(namespace_fds);
}

pub fn exec(
    allocator: std.mem.Allocator,
    cmd: []const []const u8,
    process: ProcessOptions,
) !void {
    if (cmd.len == 0) return error.CmdFailed;

    var exec_argv = cmd;
    var owns_exec_argv = false;
    if (process.argv0) |argv0| {
        const argv_copy = try allocator.alloc([]const u8, cmd.len);
        @memcpy(argv_copy, cmd);
        argv_copy[0] = argv0;
        exec_argv = argv_copy;
        owns_exec_argv = true;
    }
    defer if (owns_exec_argv) allocator.free(exec_argv);

    var env_map = if (process.clear_env)
        std.process.EnvMap.init(allocator)
    else
        try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    for (process.unset_env) |key| {
        env_map.remove(key);
    }
    for (process.set_env) |entry| {
        try env_map.put(entry.key, entry.value);
    }

    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const argv_buf = try arena.allocSentinel(?[*:0]const u8, exec_argv.len, null);
    for (exec_argv, 0..) |arg, i| {
        argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;
    }
    const file_z = (try arena.dupeZ(u8, cmd[0])).ptr;

    const envp_buf = try std.process.createNullDelimitedEnvMap(arena, &env_map);

    std.posix.execvpeZ_expandArg0(.no_expand, file_z, argv_buf.ptr, envp_buf.ptr) catch return error.CmdFailed;
}
