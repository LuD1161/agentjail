# libkrun macOS spike

Minimum-viable libkrun microVM boot on macOS arm64 (Apple Silicon, Hypervisor.framework).
Boots a tiny Alpine rootfs and prints `hello uptime=<s>` from inside the guest.

This is a research spike, not a layer. The lifecycle wrapper that the agentjail
substrate will actually use lives elsewhere; this directory just proves the API
works and measures cold-boot time.

## Requirements

- macOS 14+ on Apple Silicon (arm64). Tested on macOS 26.2 (Tahoe) / arm64.
- Homebrew.
- A C toolchain (`clang`, comes with Xcode CLI tools).
- ~50 MB free disk (libkrun deps + 4 MB alpine rootfs).

## Quick start

```sh
make            # installs libkrun via brew, builds, downloads rootfs, boots
```

Or step by step:

```sh
make deps       # brew tap slp/krun && brew install libkrun (idempotent)
make rootfs     # download + verify + extract alpine-minirootfs aarch64
make hello      # build the host binary and ad-hoc codesign with entitlements
make boot       # run a single boot
make bench      # 10 boots; print guest uptime and host wall time per run
```

## Expected output

```
[spike] krun_create_ctx + config: 2.82 ms
[spike] entering guest at host_t=2.85 ms (krun_start_enter does not return)
hello uptime=0.08
```

## Files

| File | Purpose |
|---|---|
| `hello.c` | Host binary: configure ctx, set rootfs/exec, call `krun_start_enter`. |
| `hello.entitlements.plist` | `com.apple.security.hypervisor` — required for `hv_*` calls on Apple Silicon. Ad-hoc signed; no developer cert needed. |
| `prepare-rootfs.sh` | Downloads alpine-minirootfs-3.20.3-aarch64.tar.gz (sha256-pinned), extracts to `./rootfs/`. |
| `bench.sh` | Runs `./hello` N times, prints guest uptime + host wall. |
| `Makefile` | All targets (see Quick start). |

## Notes on the measurement

`krun_start_enter` does not return on success — libkrun calls `exit()` with
the guest workload's status. So we can't measure
"krun_start_enter wall time" from the host side. Instead the guest reads
`/proc/uptime` immediately on first exec; that value upper-bounds
"krun_start_enter -> first guest userspace instruction" (the cold boot we
care about). Host wall time additionally includes dyld + krun config
(~3 ms) and process teardown.

Typical numbers on M-series, macOS 26.2:

- Guest uptime at first exec: **70-90 ms** (within the < 200 ms target in
  `docs/ENGINEERING.md` §5)
- Host wall (process start -> exit): **140-180 ms** warm, ~240 ms cold

See `tasks/findings/` for the full work log and decisions.
