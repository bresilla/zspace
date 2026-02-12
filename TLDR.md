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
