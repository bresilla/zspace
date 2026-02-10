const std = @import("std");

inline fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// voidbox run <name> <rootfs_path> <cmd>
pub const RunArgs = struct {
    name: []const u8,
    rootfs_path: []const u8,
    cmd: []const []const u8,
    resources: Resources,
    isolation: Isolation,

    pub const Isolation = struct {
        net: bool = true,
        mount: bool = true,
        pid: bool = true,
        uts: bool = true,
        ipc: bool = true,
    };

    fn parse(allocator: std.mem.Allocator, args: *std.process.ArgIterator) !RunArgs {
        var argv = std.ArrayList([]const u8).empty;
        defer argv.deinit(allocator);

        while (args.next()) |val| {
            try argv.append(allocator, val);
        }

        var resources = Resources{};
        var isolation = Isolation{};
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

        return .{
            .resources = resources,
            .isolation = isolation,
            .name = name,
            .rootfs_path = rootfs_path,
            .cmd = cmd,
        };
    }
};

pub const Resources = struct {
    mem: ?[]const u8 = null,
    cpu: ?[]const u8 = null,
    pids: ?[]const u8 = null,
};

pub const Args = union(enum) {
    run: RunArgs,
    ps,
    help,
};

pub const help =
    \\voidbox: namespace jail launcher
    \\
    \\arguments:
    \\run [resource flags] [namespace flags] <name> <rootfs_path> [cmd ...]
    \\  resource flags: -mem <val> -cpu <val> -pids <val>
    \\  namespace flags: --no-net --no-mount --no-pid --no-uts --no-ipc
    \\  default command when omitted: /bin/sh
    \\ps
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
