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

## Rootfs Mode Note (Parity)

- Bubblewrap-style behavior in voidbox uses `pivot_root` (default).
- `chroot` remains available only as an explicit voidbox extension via
  `.runtime.use_pivot_root = false`.
- `chroot` mode is less isolated than `pivot_root` and is not considered
  bubblewrap parity behavior.

## Current Hardening Status

Recent work focused on:

- netlink parser bounds/alignment hardening and malformed-input tests
- fd/resource lifecycle cleanup in spawn/network/fs paths
- synchronization protocol validation between parent/child setup phases
- stress/regression coverage (sequential + parallel launch matrices)

The project is actively hardened and tested, but still expects Linux capability/
namespace availability from the host environment.

For detailed architecture, lifecycle, parser/network hardening notes, and
operational troubleshooting, see `TLDR.md`.
