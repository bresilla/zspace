const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    if (target.result.os.tag != .linux) {
        return error.InvalidOS;
    }

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const voidbox_module = b.createModule(.{
        .root_source_file = b.path("src/voidbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    _ = b.addModule("voidbox", .{
        .root_source_file = b.path("src/voidbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "voidbox",
        .root_module = voidbox_module,
        .linkage = .static,
    });

    b.installArtifact(lib);

    const exe_unit_tests = b.addTest(.{
        .root_module = voidbox_module,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
