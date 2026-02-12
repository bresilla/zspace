# voidbox

`voidbox` is a Linux-only Zig sandboxing library with a small CLI (`vb`) for
running processes inside configurable namespace/cgroup/filesystem isolation.

## What Is In This Repo

- Static library: `lib/voidbox.zig`
- CLI: `bin/vb.zig`
- Examples: `examples/embedder_launch_shell.zig`, `examples/embedder_events.zig`
- Build graph: `build.zig`

## Requirements

- Linux host (build fails on non-Linux targets)
- Zig 0.15.x
- libc toolchain
- Optional: `direnv` (recommended in this repo)

## Build

If you use direnv:

```bash
direnv allow
direnv exec "/doc/code/voidbox" make build
```

Or directly:

```bash
make build
```

## Test

```bash
direnv exec "/doc/code/voidbox" zig build test
```

Integration tests are gated by environment variable:

```bash
VOIDBOX_RUN_INTEGRATION=1 direnv exec "/doc/code/voidbox" zig build test
```

## Install Library Artifact

```bash
make install
```

This installs:

- `~/.local/lib/libvoidbox.a`

## CLI Quick Use

```bash
direnv exec "/doc/code/voidbox" zig build vb
./zig-out/bin/vb -- /bin/sh -c 'echo hello'
```

## Library Quick Use

See in-source docs at `lib/voidbox.zig` for embedder examples:

- launch shell config
- event callback wiring

## Current Hardening Status

Recent work focused on:

- netlink parser bounds/alignment hardening and malformed-input tests
- fd/resource lifecycle cleanup in spawn/network/fs paths
- synchronization protocol validation between parent/child setup phases
- stress/regression coverage (sequential + parallel launch matrices)

The project is actively hardened and tested, but still expects Linux capability/
namespace availability from the host environment.

## Architecture Deep Dive

### High-Level Layers

- `lib/voidbox.zig`: public API surface (`launch`, `spawn`, `wait`, config/types).
- `lib/session.zig`: session orchestration, runtime init signaling, lock/status paths.
- `lib/container.zig`: process clone/fork lifecycle, namespace setup, parent/child sync.
- `lib/fs*.zig`: filesystem action execution, mounts, overlay/data source management.
- `lib/network.zig` + `lib/rtnetlink/*`: host/container veth setup, route/link/address control.
- `lib/cgroup.zig`: cgroup pathing and resource application.
- `bin/vb.zig`: bwrap-style CLI parser mapping arguments into `JailConfig`.

### Launch Flow (Conceptual)

1. Parse/construct `JailConfig` (CLI or embedder).
2. Validate config and host assumptions.
3. Initialize runtime/session state (locks/status/warnings).
4. Build container object and optional subsystems (network/cgroup/fs).
5. Spawn child with namespace flags, establish parent-child sync pipes.
6. Parent performs host-side setup; child performs in-namespace setup.
7. Child `exec`s target command; parent waits and reports outcome.
8. Teardown/cleanup (mount rollback, net/cgroup cleanup, runtime artifacts).

### Design Notes

- Runtime resource names use generated instance IDs to reduce cross-run collisions.
- Parser and netlink paths are defensive: bounds checks, frame caps, typed error returns.
- Status/event hooks are part of the core API, not only the CLI.

## Lifecycle And Event Semantics

### Session Lifecycle

- `spawn(...)` creates a live `Session`.
- `wait(&session)` is single-use and returns exit outcome.
- `deinit()` always releases owned resources (lock file handles, container state, etc.).

### Status Events

Events can be emitted through callback or fd sinks depending on `StatusOptions`.
Core event kinds include:

- `runtime_init_warnings`
- `spawned`
- `setup_finished`
- `exited`

Expected ordering for successful launches:

- `spawned` -> `setup_finished` -> `exited`

This ordering is covered by integration tests, including parallel stress scenarios.

### Parent/Child Sync Contracts

- Parent-to-child setup pipe uses a strict one-byte protocol.
- Child readiness signaling uses explicit one-byte ack semantics.
- Short reads/writes and protocol-byte violations are treated as errors.

## Troubleshooting And Operational Notes

### Common Failure Buckets

- `SpawnFailed`: host namespace/capability restrictions or setup failure path.
- user namespace mapping failures (`uid_map`/`gid_map` write restrictions).
- network setup failures (missing privileges, iptables availability, interface state).

### Quick Checks

```bash
direnv exec "/doc/code/voidbox" zig build test
direnv exec "/doc/code/voidbox" make build
```

For integration coverage:

```bash
VOIDBOX_RUN_INTEGRATION=1 direnv exec "/doc/code/voidbox" zig build test
```

### Runtime Requirements

- Namespace and cgroup behavior depends on host kernel policy and privileges.
- Some integration tests intentionally skip when host capabilities are unavailable.

### Performance Notes

- NAT/default-route setup uses caching paths to reduce repeated process/network overhead.
- Netlink parsing paths are hardened with bounded loops to avoid pathological scans.
- Parallel stress tests are included to catch race/lifecycle regressions early.
