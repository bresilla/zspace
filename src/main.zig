const std = @import("std");
const args = @import("args.zig");
const ps = @import("ps.zig");
const voidbox = @import("voidbox.zig");

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena_allocator.allocator();
    const cmd = try args.parseArgs(allocator);

    switch (cmd) {
        .run => |r| {
            const config: voidbox.JailConfig = .{
                .name = r.name,
                .rootfs_path = r.rootfs_path,
                .cmd = r.cmd,
                .resources = .{
                    .mem = r.resources.mem,
                    .cpu = r.resources.cpu,
                    .pids = r.resources.pids,
                },
                .isolation = .{
                    .net = r.isolation.net,
                    .mount = r.isolation.mount,
                    .pid = r.isolation.pid,
                    .uts = r.isolation.uts,
                    .ipc = r.isolation.ipc,
                },
            };
            _ = try voidbox.launch(config, allocator);
        },
        .help => {
            const stdout = std.fs.File.stdout().deprecatedWriter();
            _ = try stdout.write(args.help);
        },
        .ps => {
            const containers = try ps.runningContainers(allocator);
            var stdout = std.fs.File.stdout().deprecatedWriter();
            _ = try stdout.print("Running Containers:\n", .{});
            for (containers) |c| {
                try c.print(stdout);
            }
        },
        .doctor => {
            const report = try voidbox.check_host(allocator);
            const stdout = std.fs.File.stdout().deprecatedWriter();
            try report.print(stdout);
        },
    }
}
