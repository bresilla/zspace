const std = @import("std");
const voidbox = @import("voidbox");

const EventState = struct {
    spawned: usize = 0,
    exited: usize = 0,
};

fn onEvent(ctx: ?*anyopaque, event: voidbox.StatusEvent) !void {
    const state: *EventState = @ptrCast(@alignCast(ctx.?));
    switch (event.kind) {
        .runtime_init_warnings => {},
        .spawned => state.spawned += 1,
        .setup_finished => {},
        .exited => state.exited += 1,
    }
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var state = EventState{};
    const cfg: voidbox.JailConfig = .{
        .name = "example-events",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "exit 0" },
        .status = .{
            .on_event = onEvent,
            .callback_ctx = &state,
        },
        .isolation = .{
            .user = true,
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
        },
    };

    _ = try voidbox.launch(cfg, allocator);
    if (state.spawned == 0 or state.exited == 0) return error.MissingLifecycleEvents;
}
