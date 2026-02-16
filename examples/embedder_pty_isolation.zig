const std = @import("std");
const voidbox = @import("voidbox");
const linux = std.os.linux;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Configuration for filesystem isolation
    const config = voidbox.JailConfig{
        .name = "pty-sandbox",
        .rootfs_path = "/",
        .cmd = &.{"/bin/bash"},
        .isolation = .{
            .user = true,
            .net = true,
            .mount = true,
            .pid = true,
            .uts = false,
            .ipc = true,
            .cgroup = false,
        },
        .runtime = .{
            .use_pivot_root = false, // Use chroot for simplicity in this example
            .hostname = "sandbox",
        },
        .fs_actions = &.{
            .{ .proc = "/proc" },
            .{ .dev = "/dev" },
            .{ .tmpfs = .{ .dest = "/tmp" } },
            .{ .ro_bind = .{ .src = "/usr", .dest = "/usr" } },
            .{ .ro_bind = .{ .src = "/lib", .dest = "/lib" } },
            .{ .ro_bind = .{ .src = "/lib64", .dest = "/lib64" } },
            .{ .ro_bind = .{ .src = "/bin", .dest = "/bin" } },
        },
    };

    try voidbox.validate(config);

    std.debug.print("=== PTY-Friendly Isolation Example ===\n", .{});
    std.debug.print("This example demonstrates using applyIsolationInChild() for PTY setup.\n", .{});
    std.debug.print("In a real PTY scenario, you would setup pseudo-terminals before applying isolation.\n\n", .{});

    // Fork for PTY setup
    const pid = try std.posix.fork();

    if (pid == 0) {
        // Child process

        // TODO: Setup PTY here (pseudo-terminal for interactive shell)
        // This is where Hexe would setup PTY master/slave
        // For this example, we skip PTY setup and just demonstrate the API

        std.debug.print("[Child] Applying voidbox isolation...\n", .{});

        // Apply voidbox isolation in the already-forked child
        voidbox.applyIsolationInChild(config, allocator) catch |err| {
            std.debug.print("[Child] Failed to apply isolation: {}\n", .{err});
            std.posix.exit(1);
        };

        std.debug.print("[Child] Isolation applied successfully. Exec'ing command...\n", .{});

        // Now exec the command
        const envp = [_:null]?[*:0]const u8{null};
        const argv = [_:null]?[*:0]const u8{
            "/bin/echo",
            "Hello from isolated environment!",
            null,
        };

        const err = linux.execve("/bin/echo", &argv, &envp);
        std.debug.print("[Child] execve failed: {}\n", .{err});
        std.posix.exit(127);
    }

    // Parent process - wait for child
    std.debug.print("[Parent] Waiting for child process (pid={d})...\n", .{pid});
    const wait_result = std.posix.waitpid(pid, 0);

    // Decode wait status
    const c = @cImport({
        @cInclude("sys/wait.h");
    });
    const status = @as(c_int, @bitCast(wait_result.status));
    const exit_code: u8 = if (c.WIFEXITED(status))
        @intCast(c.WEXITSTATUS(status))
    else if (c.WIFSIGNALED(status))
        @intCast((128 + c.WTERMSIG(status)) & 0xff)
    else
        1;

    std.debug.print("[Parent] Child exited with code: {d}\n", .{exit_code});
    std.posix.exit(exit_code);
}
