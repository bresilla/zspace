const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var shell_cfg = voidbox.default_shell_config("/");
    shell_cfg.name = "example-shell";
    shell_cfg.shell_args = &.{ "-c", "echo voidbox embedder example" };
    shell_cfg.isolation = .{
        .user = true,
        .net = false,
        .mount = false,
        .pid = false,
        .uts = false,
        .ipc = false,
    };

    _ = try voidbox.launch_shell(shell_cfg, allocator);
}
