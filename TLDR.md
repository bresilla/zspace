## TL;DR Deep Reference

This document is a detailed technical companion to `README.md`.

It covers:

- architecture and module boundaries
- runtime lifecycle semantics
- parent/child synchronization contracts
- networking and rtnetlink behavior
- filesystem action execution and rollback
- cgroup/runtime warning behavior
- test strategy and stress coverage
- known remaining limitations

---

## 1) Project Intent

`voidbox` provides a Linux-focused process isolation toolkit in Zig.

The library is built for embedders that need:

- namespace isolation controls
- filesystem mount/action composition
- cgroup resource constraints
- optional container-side networking setup
- lifecycle status/event signaling

The CLI (`vb`) offers a bwrap-like argument surface that maps into the same
library configuration model.

---

## 2) Module Map

### Public API

- `lib/voidbox.zig`
  - re-exports key config and runtime types
  - entry points: `launch`, `spawn`, `wait`, `launch_shell`, `check_host`

### Lifecycle Core

- `lib/session.zig`
  - top-level spawn orchestration
  - runtime init warnings
  - status event emissions
  - lock file handling

- `lib/container.zig`
  - clone/fork process tree setup
  - parent/child pipe synchronization
  - namespace transition choreography
  - PID1 behavior when configured

### Isolation Subsystems

- `lib/fs.zig`, `lib/fs_actions.zig`, `lib/mounts.zig`
  - rootfs and mount action execution
  - rollback and artifact cleanup logic

- `lib/network.zig`, `lib/ip.zig`
  - veth/bridge pathing
  - address assignment strategy
  - NAT setup

- `lib/rtnetlink/*`
  - netlink socket and route/link/address operations
  - strict parser validation and bounded loops

- `lib/cgroup.zig`
  - cgroup path entry and resource file writes

### CLI Adapter

- `bin/vb.zig`
  - argument parsing
  - parser-owned allocation tracking
  - mapping to `JailConfig`

---

## 3) Launch Lifecycle

Conceptual flow:

1. construct `JailConfig`
2. validate config/host assumptions
3. create container/session internals
4. spawn process tree with requested isolation
5. synchronize parent and child setup phases
6. execute target command
7. emit status events and collect exit
8. cleanup resources and runtime artifacts

Important behavior:

- `launch` is a convenience wrapper over `spawn` + `wait`.
- `wait` is intentionally single-use per session.
- cleanup is designed to happen on both success and error paths.

---

## 4) Parent/Child Sync Contracts

Two key handshake channels exist in the spawn pipeline.

### Parent-to-child setup gate

- one-byte protocol used to release child setup continuation
- child validates both byte length and expected byte value

### Child-to-parent setup-ready ack

- child writes readiness byte once setup reaches the expected checkpoint
- parent validates exact one-byte read and expected value

Failure modes are surfaced as explicit errors rather than silent continuation.

---

## 5) Status/Event Semantics

Event stream can go to callback and/or fd sinks.

Observed event kinds include:

- `runtime_init_warnings`
- `spawned`
- `setup_finished`
- `exited`

Expected ordering for successful launch path:

- `spawned` -> `setup_finished` -> `exited`

Ordering is covered in integration tests, including parallel stress paths.

---

## 6) Runtime Warning Model

Runtime initialization can detect degraded states (for example cgroup controller
write constraints).

The current model supports:

- warning accumulation
- event surfacing
- optional policy to fail fast when warnings are present

This avoids silently continuing in degraded conditions without visibility.

---

## 7) Networking Behavior

Networking setup includes:

- bridge setup
- veth creation and namespace move
- container-side interface configuration
- route and resolver setup
- optional NAT enablement

Hardening highlights:

- deterministic IPv4 collision fallback attempts
- cached default interface lookup with invalidation when interface disappears
- NAT reconfigure guard to avoid repeated redundant setup
- safer child termination status checks for external command execution

Teardown behavior:

- attempts to remove created veth side
- ignores `NotFound` as a non-fatal teardown case
- always deinitializes netlink resources

---

## 8) Rtnetlink Parser Safety

Core parser hardening includes:

- strict header/frame length checks
- netlink alignment-aware frame stepping
- validation of attribute length and bounds
- explicit handling of supported/unsupported message types
- bounded frame/packet/attribute iteration caps
- robust ACK/NACK parsing from minimal payloads
- trailing non-zero padding rejection

Route parsing currently emphasizes IPv4 attributes with explicit unsupported
handling for non-supported families where needed.

---

## 9) Filesystem Action Execution

`fs_actions` handles mount and artifact operations for:

- bind/ro bind variants
- proc/dev/tmpfs/mqueue
- dir/file/chmod/symlink
- overlay/tmp_overlay/ro_overlay
- inline data binding via temporary files

Hardening highlights:

- rollback helpers for mounted targets
- temp file/dir cleanup helpers
- instance artifact cleanup helpers
- absolute path handling without cwd leakage
- temporary file cleanup on write/read failure paths

---

## 9.1) Root Filesystem Isolation: chroot vs pivot_root

voidbox supports two mechanisms for changing the root filesystem:

Parity note:

- Bubblewrap-style semantics correspond to `pivot_root` flow.
- `chroot` is intentionally kept as a voidbox-only extension mode.
- Treat `chroot` as a compatibility/debug tool, not as parity behavior.

### pivot_root (Default, Recommended)

**What it does:**
- Fully switches the mount namespace's root filesystem
- Unmounts and detaches the old root completely
- Provides strongest isolation - old root is inaccessible after pivot

**When to use:**
- Production containers (default behavior)
- When maximum security is required
- Modern container runtimes (Docker, Podman use this)

**Configuration:**
```zig
.runtime = .{ .use_pivot_root = true }  // default
```

**CLI:**
```bash
vb --pivot-root --rootfs /my-rootfs -- /bin/sh  # explicit
vb --rootfs /my-rootfs -- /bin/sh               # default
```

### chroot (Legacy)

**What it does:**
- Changes root directory for the process tree
- Old root remains accessible via file descriptors
- Simpler but less secure

**When to use:**
- Nested containers (pivot_root may fail inside containers)
- Debugging scenarios
- Legacy compatibility

**Configuration:**
```zig
.runtime = .{ .use_pivot_root = false }
```

**CLI:**
```bash
vb --no-pivot-root --rootfs /my-rootfs -- /bin/sh
vb --chroot --rootfs /my-rootfs -- /bin/sh         # alias
```

### Security Comparison

| Feature | chroot | pivot_root |
|---------|--------|------------|
| Old root accessible | Yes (via FDs) | No (unmounted) |
| Escape prevention | Weak | Strong |
| Used by Docker | No | Yes |
| Kernel requirement | Any | Mount namespace |

**Recommendation:** Always use pivot_root unless you have a specific reason not to.

---

## 9.2) Advanced API: applyIsolationInChild()

For advanced use cases where you need to fork yourself (e.g., PTY setup), use the decoupled isolation API:

### Overview

```zig
const pid = try std.posix.fork();
if (pid == 0) {
    // Child: setup PTY or other custom pre-isolation setup
    try myCustomSetup();

    // Apply voidbox isolation in already-forked child
    try voidbox.applyIsolationInChild(config, allocator);

    // Exec command
    try std.posix.execveZ(...);
}
// Parent: continues...
```

### Use Cases

- PTY setup before isolation (terminal emulators, shells like Hexe)
- Custom FD inheritance patterns
- Advanced IPC setup before namespace isolation
- Any scenario requiring fork control before isolation

### What it Does

`applyIsolationInChild()` applies the following in order:

1. Namespace attachments (if `namespace_fds` provided)
2. PID namespace setup (handles second fork if needed)
3. Security context pre-exec setup (uid/gid, capabilities, no_new_privs)
4. Hostname (if in UTS namespace)
5. Filesystem isolation (pivot_root/chroot + fs_actions)
6. Network interface setup (if in network namespace)
7. Final namespace attachments (user2 if provided)
8. User namespace policy enforcement (`disable_userns` / assertion)
9. Late seccomp application (immediately before caller exec)

### What it Does NOT Do

- Does NOT fork - you control the fork
- Does NOT exec - you call exec after isolation returns
- Does NOT setup user namespace mappings - parent must handle this

### Prerequisites

- Must be called in child process after fork
- Parent must write user namespace mappings (uid_map/gid_map) if using user namespaces
- Caller responsible for exec after this returns

### Example

See `examples/embedder_pty_isolation.zig` for a complete working example.

### Comparison with Normal API

| Aspect | `launch()`/`spawn()` | `applyIsolationInChild()` |
|--------|---------------------|---------------------------|
| Fork control | voidbox forks | Caller forks |
| Exec control | voidbox execs | Caller execs |
| User ns mapping | Automatic | Manual (parent responsibility) |
| PTY support | No | Yes |
| Simplicity | Simple | Advanced |

---

## 10) PID1 Mode Notes

Current PID1 behavior includes:

- signal forwarding set for common termination/control signals
- process-group-first forwarding fallback to child pid
- wait loop tracking main child identity
- additional non-blocking reap pass
- signal handler reset/rollback protections

This is robust for common operational cases, but not yet a full init-system
replacement semantics set.

---

## 11) CLI Parser Ownership Model

`bin/vb.zig` tracks parser-created dynamic strings in an explicit owned list.

This covers:

- generated `/proc/self/fd/<n>` sources for bind-fd options
- overlay key material
- nested `--args` expansion string duplicates

Recent hardening ensures ownership transfer is explicit in failure paths, with
cleanup coverage for nested expansion errors.

---

## 12) Testing Strategy

Testing layers:

- unit tests for helper/math/parser functions
- regression tests for malformed netlink frames/attrs
- lifecycle tests for session semantics
- stress tests (sequential and parallel launch matrices)
- integration tests gated by `VOIDBOX_RUN_INTEGRATION`

Additional stability checks include fd-count regression tests for repeated
init/deinit cycles in selected subsystems.

---

## 13) Build And Validation Commands

Recommended in this repo:

```bash
direnv allow
direnv exec "/doc/code/voidbox" zig build test
direnv exec "/doc/code/voidbox" make build
```

Integration-enabled test run:

```bash
VOIDBOX_RUN_INTEGRATION=1 direnv exec "/doc/code/voidbox" zig build test
```

---

## 14) Operational Caveats

- Linux-only build target.
- Real behavior depends on host namespace/cgroup policy and privileges.
- Some integration tests intentionally skip on constrained hosts.
- External tooling assumptions (such as iptables availability) can affect
  selected network paths.

---

## 15) Known Remaining Gaps (Practical)

1. PID1 behavior is strong but not full init-grade semantics.
2. Full IPv6 route attribute support is still deferred.
3. Some failure-injection matrix scenarios remain difficult to unit-simulate
   without heavier test harnessing.

---

## 16) Suggested Next Steps

If further hardening is needed, prioritize:

1. deeper PID1 behavioral conformance tests under signal storms
2. expanded privileged integration matrix for network+cgroup combinations
3. optional IPv6 route attribute support path with explicit compatibility tests

---

## 17) Short Command Cookbook

Build:

```bash
make build
```

Run tests:

```bash
zig build test
```

Build CLI only:

```bash
zig build vb
```

Run CLI example:

```bash
./zig-out/bin/vb -- /bin/sh -c 'echo hello from voidbox'
```

---

## 18) Minimal Embedder Pattern

Pseudo-usage pattern:

1. create default shell config
2. override isolation options
3. launch
4. inspect exit code

For concrete snippets, use `lib/voidbox.zig` module docs and `examples/`.

---

## 19) File Pointers

- API: `lib/voidbox.zig`
- Session: `lib/session.zig`
- Container spawn/PID1: `lib/container.zig`
- Network: `lib/network.zig`
- Netlink core: `lib/rtnetlink/rtnetlink.zig`
- Route parser: `lib/rtnetlink/route/get.zig`
- Link parser: `lib/rtnetlink/link/get.zig`
- FS actions: `lib/fs_actions.zig`
- CLI parser: `bin/vb.zig`

---

## 20) Summary

The codebase has undergone substantial hardening in parser safety,
resource lifecycle management, synchronization correctness, and stress
coverage. The current system is practical and robust for Linux hosts with
appropriate namespace/cgroup capabilities, with a small set of explicit
advanced gaps remaining.

---

## 21) Extended Code Cookbook (35 Patterns)

### Sample 01: Minimal launch with defaults

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s01", .rootfs_path = "/", .cmd = &.{ "/bin/true" } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 02: Shell command with explicit args

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    var cfg = voidbox.default_shell_config("/");
    cfg.name = "s02";
    cfg.shell_args = &.{ "-c", "echo hi" };
    _ = try voidbox.launch_shell(cfg, std.heap.page_allocator);
}
```

### Sample 03: Status callback capture

```zig
const std = @import("std");
const voidbox = @import("voidbox");

fn onEvent(_: ?*anyopaque, ev: voidbox.StatusEvent) !void {
    std.debug.print("kind={any}\n", .{ev.kind});
}

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s03", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .status = .{ .on_event = onEvent } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 04: Explicit chdir before exec

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{
        .name = "s04", .rootfs_path = "/", .cmd = &.{ "/bin/pwd" },
        .process = .{ .chdir = "/tmp" },
    };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 05: Clear environment and set one variable

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const env = [_]voidbox.EnvironmentEntry{.{ .key = "HELLO", .value = "WORLD" }};
    const cfg: voidbox.JailConfig = .{ .name = "s05", .rootfs_path = "/", .cmd = &.{ "/usr/bin/env" }, .process = .{ .clear_env = true, .set_env = &env } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 06: Unset selected env variables

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const unset = [_][]const u8{"PATH", "HOME"};
    const cfg: voidbox.JailConfig = .{ .name = "s06", .rootfs_path = "/", .cmd = &.{ "/usr/bin/env" }, .process = .{ .unset_env = &unset } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 07: PID namespace without network namespace

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{
        .name = "s07", .rootfs_path = "/", .cmd = &.{ "/bin/true" },
        .isolation = .{ .pid = true, .net = false, .user = false, .mount = false, .uts = false, .ipc = false, .cgroup = false },
    };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 08: UTS namespace with hostname override

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s08", .rootfs_path = "/", .cmd = &.{ "/bin/hostname" }, .isolation = .{ .uts = true }, .runtime = .{ .hostname = "voidbox-demo" } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 09: Mount namespace only

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s09", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .isolation = .{ .mount = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 10: Lock file status synchronization

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s10", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .status = .{ .lock_file_path = "/tmp/voidbox.lock" } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 11: Add filesystem bind action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .bind = .{ .src = "/usr", .dest = "/mnt/usr" } }};
    const cfg: voidbox.JailConfig = .{ .name = "s11", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 12: Read-only bind action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .ro_bind = .{ .src = "/etc", .dest = "/mnt/etc" } }};
    const cfg: voidbox.JailConfig = .{ .name = "s12", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 13: tmpfs mount action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .tmpfs = .{ .dest = "/tmp/sandbox", .size_bytes = 1 << 20, .mode = 0o700 } }};
    const cfg: voidbox.JailConfig = .{ .name = "s13", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 14: Overlay source + overlay mount

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{
        .{ .overlay_src = .{ .key = "base", .path = "/lower" } },
        .{ .overlay = .{ .source_key = "base", .upper = "/upper", .work = "/work", .dest = "/merged" } },
    };
    const cfg: voidbox.JailConfig = .{ .name = "s14", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 15: Temporary overlay action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{
        .{ .overlay_src = .{ .key = "base", .path = "/lower" } },
        .{ .tmp_overlay = .{ .source_key = "base", .dest = "/merged" } },
    };
    const cfg: voidbox.JailConfig = .{ .name = "s15", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 16: Inline data bind action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .bind_data = .{ .data = "abc", .dest = "/tmp/file" } }};
    const cfg: voidbox.JailConfig = .{ .name = "s16", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 17: Read-only inline data bind action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .ro_bind_data = .{ .data = "abc", .dest = "/tmp/file" } }};
    const cfg: voidbox.JailConfig = .{ .name = "s17", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 18: File action with data payload

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .file = .{ .path = "/tmp/hello.txt", .data = "hello" } }};
    const cfg: voidbox.JailConfig = .{ .name = "s18", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 19: Create symlink action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .symlink = .{ .target = "/bin/sh", .path = "/tmp/sh" } }};
    const cfg: voidbox.JailConfig = .{ .name = "s19", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 20: chmod action

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const actions = [_]voidbox.FsAction{.{ .chmod = .{ .path = "/tmp/x", .mode = 0o700 } }};
    const cfg: voidbox.JailConfig = .{ .name = "s20", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .fs_actions = &actions };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 21: as_pid_1 mode in pid namespace

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{
        .name = "s21", .rootfs_path = "/", .cmd = &.{ "/bin/true" },
        .isolation = .{ .pid = true }, .runtime = .{ .as_pid_1 = true },
    };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 22: Enable new session behavior

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s22", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .process = .{ .new_session = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 23: Die with parent flag

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s23", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .process = .{ .die_with_parent = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 24: Capability add example

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const caps = [_]u8{std.os.linux.CAP.NET_ADMIN};
    const cfg: voidbox.JailConfig = .{ .name = "s24", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .security = .{ .cap_add = &caps } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 25: Capability drop example

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const caps = [_]u8{std.os.linux.CAP.NET_RAW};
    const cfg: voidbox.JailConfig = .{ .name = "s25", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .security = .{ .cap_drop = &caps } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 26: Fail on runtime warnings policy

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s26", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .runtime = .{ .fail_on_runtime_warnings = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 27: Namespace FDs injection

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const nfd: voidbox.NamespaceFds = .{ .net = 10, .mount = 11 };
    const cfg: voidbox.JailConfig = .{ .name = "s27", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .namespace_fds = nfd };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 28: Lock + info fd

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s28", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .status = .{ .lock_file_path = "/tmp/voidbox.lock", .info_fd = 1 } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 29: JSON status fd output

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s29", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .status = .{ .json_status_fd = 1 } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 30: Explicit argv0 override

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s30", .rootfs_path = "/", .cmd = &.{ "/bin/echo", "ok" }, .process = .{ .argv0 = "custom-echo" } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 31: Disable userns path

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s31", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .security = .{ .disable_userns = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 32: Assert userns disabled

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const cfg: voidbox.JailConfig = .{ .name = "s32", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .security = .{ .assert_userns_disabled = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 33: Security labels

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const sec: voidbox.SecurityOptions = .{ .exec_label = "system_u:system_r:container_t:s0", .file_label = "system_u:object_r:container_file_t:s0" };
    const cfg: voidbox.JailConfig = .{ .name = "s33", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .security = sec };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 34: Resource limits skeleton

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    const limits: voidbox.ResourceLimits = .{ .memory_max = "268435456", .cpu_max = "50000 100000", .pids_max = "256" };
    const cfg: voidbox.JailConfig = .{ .name = "s34", .rootfs_path = "/", .cmd = &.{ "/bin/true" }, .resources = limits, .isolation = .{ .cgroup = true } };
    _ = try voidbox.launch(cfg, std.heap.page_allocator);
}
```

### Sample 35: Session API usage

```zig
const std = @import("std");
const voidbox = @import("voidbox");

pub fn main() !void {
    var cfg: voidbox.JailConfig = .{ .name = "s35", .rootfs_path = "/", .cmd = &.{ "/bin/true" } };
    var session = try voidbox.spawn(cfg, std.heap.page_allocator);
    defer session.deinit();
    _ = try voidbox.wait(&session);
}
```

---

## 22) Extended Hardening Checklist (HC-001 to HC-150)

- HC-001: validate all public API error surfaces are typed and documented.
- HC-002: avoid silent fallthrough on parser unknown options.
- HC-003: enforce strict option arity checks in CLI parser.
- HC-004: maintain explicit ownership transfer when storing allocated strings.
- HC-005: pair every parser allocation path with tested error cleanup.
- HC-006: keep status event ordering deterministic under parallel runs.
- HC-007: assert `wait` single-use semantics in tests.
- HC-008: validate lock acquisition and re-acquisition behavior.
- HC-009: keep lock-file behavior deterministic across process exits.
- HC-010: validate parent/child sync protocol byte values.
- HC-011: validate parent/child sync byte counts.
- HC-012: treat short sync writes as hard failures.
- HC-013: treat short sync reads as hard failures.
- HC-014: ensure early spawn failures kill and reap children.
- HC-015: ensure pipe setup failure closes already-opened fds.
- HC-016: ensure all fd closures are idempotent in errdefer paths.
- HC-017: assert PID1 forwarding signal set explicitly.
- HC-018: assert forbidden PID1 signals are excluded.
- HC-019: rollback PID1 signal handlers on install failure.
- HC-020: reset PID1 signal handlers after supervision.
- HC-021: forward to process group first, child pid fallback second.
- HC-022: ensure zombie reaping pass after main child exit.
- HC-023: ensure `sethostname` failures propagate.
- HC-024: do not ignore syscall return values in setup path.
- HC-025: ensure fs runtime artifact cleanup runs on wait completion.
- HC-026: ensure fs cleanup covers both success and failure outcomes.
- HC-027: keep absolute path handling independent of cwd.
- HC-028: avoid relative path leakage into repo directory.
- HC-029: delete temporary source files on fs-action failures.
- HC-030: cleanup temporary overlay dirs on mount failures.
- HC-031: verify cleanup helpers remove temp files.
- HC-032: verify cleanup helpers remove temp dirs.
- HC-033: verify instance artifact cleanup removes overlay/data trees.
- HC-034: avoid double-free in cleanup path ownership.
- HC-035: ensure rollback unmount order is reverse application order.
- HC-036: tolerate busy unmount semantics where intended.
- HC-037: cap parser loops on netlink frame counts.
- HC-038: cap parser loops on netlink packet counts.
- HC-039: cap parser loops on netlink attribute counts.
- HC-040: reject malformed netlink header lengths.
- HC-041: reject malformed netlink attribute lengths.
- HC-042: reject non-zero netlink trailing padding bytes.
- HC-043: reject unexpected netlink message types.
- HC-044: parse ACK/NACK from minimal valid payloads.
- HC-045: validate ACK error-code ranges.
- HC-046: map EEXIST to explicit Exists error.
- HC-047: map unknown ACK errno values to generic error.
- HC-048: reject positive ACK errno values as invalid response.
- HC-049: reject min-int overflow ACK errno input.
- HC-050: align route frame stepping with netlink alignment.
- HC-051: align link frame stepping with netlink alignment.
- HC-052: ensure route parser enforces frame bounds before decode.
- HC-053: ensure link parser enforces frame bounds before decode.
- HC-054: validate IFNAME payload null termination.
- HC-055: free owned IFNAME allocations in deinit paths.
- HC-056: verify repeated link parse/deinit does not leak.
- HC-057: verify repeated route parse/deinit does not leak.
- HC-058: verify rtnetlink init/deinit fd count stability.
- HC-059: verify network init/deinit fd count stability.
- HC-060: avoid unbounded route dump accumulation.
- HC-061: cap route message collection during dumps.
- HC-062: treat successful route ERROR ACK as stream terminator.
- HC-063: keep route parser family checks explicit for IPv4 attrs.
- HC-064: return unsupported-family errors for unsupported route attrs.
- HC-065: parse IPv4 destination attribute.
- HC-066: parse IPv4 gateway attribute.
- HC-067: parse IPv4 preferred source attribute.
- HC-068: parse output interface attribute with strict length checks.
- HC-069: expand route attr tests for destination/prefsrc cases.
- HC-070: ensure network teardown always deinitializes netlink handle.
- HC-071: treat not-found veth during teardown as non-fatal.
- HC-072: preserve first meaningful teardown error when multiple occur.
- HC-073: ensure moved veth lookup objects are deinitialized.
- HC-074: ensure addrAdd message deinit executes on all paths.
- HC-075: prefer writeAll for cgroup/runtime control writes.
- HC-076: never rely on debug assertions for I/O correctness.
- HC-077: ensure cgroup controller setup failures emit warnings.
- HC-078: support fail-on-runtime-warnings policy.
- HC-079: emit runtime warning status events when warnings exist.
- HC-080: include warning count in status payload.
- HC-081: clip warning count payload to bounded integer range.
- HC-082: test status callback path for runtime warnings.
- HC-083: test status json output path for runtime warnings.
- HC-084: keep default gateway lookup ownership stable after deinit.
- HC-085: match gateway and output interface from same route message.
- HC-086: cache default gateway ifname when valid.
- HC-087: invalidate cached ifname when link disappears.
- HC-088: avoid repeated NAT setup when state unchanged.
- HC-089: handle child process termination status robustly.
- HC-090: avoid direct union-field assumptions on process term state.
- HC-091: provide deterministic IPv4 collision fallback attempts.
- HC-092: bound address-attempt loop to finite pool size.
- HC-093: return explicit pool-exhausted error when no addresses remain.
- HC-094: add deterministic tests for address attempt wrapping.
- HC-095: add deterministic tests for attempt rotation.
- HC-096: keep parser side-effects out of argument fetch helpers.
- HC-097: avoid unconditional stderr writes during parser errors.
- HC-098: ensure parser unknown-option errors remain explicit.
- HC-099: ensure nested --args expansion depth is bounded.
- HC-100: verify parser cleanup under nested expansion failures.
- HC-101: ensure allocOwnedPrint frees on append failure.
- HC-102: ensure readArgVector ownership transfer is failure-safe.
- HC-103: ensure parser deinit frees all owned string slices.
- HC-104: ensure parser deinit frees command/env/cap arrays.
- HC-105: test seccomp fd conflict validation.
- HC-106: test dangling perms/size modifier validation.
- HC-107: test bind-fd source mapping behavior.
- HC-108: keep integration tests gated behind explicit env toggle.
- HC-109: skip integration tests gracefully on constrained hosts.
- HC-110: maintain sequential launch stress coverage.
- HC-111: maintain parallel netless launch stress coverage.
- HC-112: maintain parallel namespace-toggle stress coverage.
- HC-113: maintain parallel status-callback stress coverage.
- HC-114: assert event ordering in callback stress paths.
- HC-115: include as_pid_1 launch-path integration coverage.
- HC-116: keep spawn/wait lifecycle tests for single-wait behavior.
- HC-117: ensure wait-after-wait returns SessionAlreadyWaited.
- HC-118: preserve clear error mapping in public launch API.
- HC-119: preserve doctor/check_host error typing.
- HC-120: keep Linux-only build guard in build graph.
- HC-121: ensure example binaries compile with main build graph.
- HC-122: keep README command examples aligned with Makefile targets.
- HC-123: keep direnv usage documented for reproducible environment.
- HC-124: keep integration command examples documented.
- HC-125: avoid committing generated local temp directories.
- HC-126: avoid force-adding intentionally ignored files.
- HC-127: prefer concise focused commits per hardening topic.
- HC-128: run tests/build after each meaningful batch.
- HC-129: preserve rollback behavior when parent setup partially succeeds.
- HC-130: preserve error context in failure returns.
- HC-131: prevent silent panic paths in parser/runtime flows.
- HC-132: replace unreachable panics with explicit errors.
- HC-133: keep netlink parser behavior deterministic under malformed input.
- HC-134: ensure parser refuses truncated frames.
- HC-135: ensure parser refuses overrunning attrs.
- HC-136: ensure parser rejects unexpected frame payload shape.
- HC-137: keep helper tests small and deterministic.
- HC-138: isolate lock-file tests with unique tmp path.
- HC-139: clean lock-file test artifacts after execution.
- HC-140: keep API examples minimal and copy-paste friendly.
- HC-141: keep complex examples realistic but host-portable.
- HC-142: keep fallback semantics documented for spawn failures.
- HC-143: ensure network teardown behavior remains idempotent.
- HC-144: ensure cleanup functions tolerate missing paths.
- HC-145: keep retry/collision loops finite and observable.
- HC-146: preserve warning visibility in both log and event channels.
- HC-147: avoid stale-cache assumptions in dynamic network state.
- HC-148: keep fs helper ownership contracts explicit.
- HC-149: prefer small pure helper functions for critical checks.
- HC-150: keep this checklist updated whenever a hardening delta lands.

---

## 23) Quick Debug Notes

- DN-001: if `zig build test` fails in integration paths, re-run with integration toggle disabled first.
- DN-002: if network tests fail, confirm host has required netns/capability support.
- DN-003: if cgroup writes fail, inspect controller availability under `/sys/fs/cgroup`.
- DN-004: if lock tests fail intermittently, clear stale files in `/tmp`.
- DN-005: if status ordering fails, inspect callback path and sync fd wiring.
- DN-006: if spawn fails early, inspect pipe/clone error returns first.
- DN-007: if parser tests fail, isolate `--args` nested expansion case.
- DN-008: if fd stability tests fail, inspect newly added handles in setup/teardown paths.
- DN-009: if netlink parsing fails, check header/attr length assumptions against kernel payload.
- DN-010: if cleanup tests fail, verify absolute path handling and rootfs mapping semantics.
