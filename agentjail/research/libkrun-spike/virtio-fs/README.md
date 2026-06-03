# libkrun macOS spike — virtio-fs host workdir mount

Mounts a host directory inside the guest via `krun_add_virtiofs(ctx, tag,
host_path)`, exercises bidirectional file IO from the guest, and proves
out-of-mount paths are invisible.

Sibling of `../` (minimal boot) and `../kernel/` (custom kernel). Neither
is modified; this directory adds the third orthogonal demonstration of the
libkrun API surface.

## Requirements

- macOS 14+ on Apple Silicon (arm64). Tested on macOS 26.2 / arm64.
- Homebrew + libkrun 1.18.1 (installed by `make -C .. deps`).
- A rootfs prepared by `make -C .. rootfs`.

## Quick start

```sh
make            # build, run boot, write a file from inside the VM
make verify     # build, run boot, then assert host sees the guest's write
                # AND that out-of-mount paths fail (isolation)
make bench      # 10 boots; print guest uptime + host wall per run
```

By default the spike mounts `./workdir/` (created by `make`) as the
shared volume. Override with `WORKDIR=/path/to/dir make boot`.

## Host ↔ guest path mapping convention

Codified here and in `agentjail/docs/DECISIONS.md` (virtio-fs workdir entry):

| Aspect | Value | Rationale |
|---|---|---|
| virtio-fs tag | `agentwork` | One tag → one project. Future agentjail microVMs will use the same tag for the user's project dir, so guest userland (and policy code that introspects `/proc/mounts`) sees a stable name. |
| Guest mountpoint | `/work` | Short, top-level, no collision with FHS dirs. `cd /work` is the agent's working directory. |
| Host path | `$PWD` of the launcher (overridable via `WORKDIR=…`) | The agent sees only the project the user invoked it from, never the rest of the filesystem. |
| Mode | RW | The agent must write its outputs back. A future mount-policy task may add a read-only auxiliary mount for caches. |
| uid / gid mapping | identity (no remap) | libkrun 1.18 `krun_add_virtiofs` does not expose a uid_map argument; guest writes land as the host user. See findings "Things noticed" for the hardening follow-up. |

Only this one mount + the rootfs are addressable from inside the guest;
every other host path is invisible. The `verify` target asserts this by
attempting to `cat /opt/homebrew/Cellar` from inside the guest and
requiring a non-zero exit.

## Expected output (`make verify`)

```
----- guest stdout -----
[spike] virtio-fs tag=agentwork -> host:/.../workdir mounted at guest:/work
[spike] krun_create_ctx + config: 2.40 ms
[spike] entering guest at host_t=2.45 ms
hello uptime=0.07
from-host-payload=hello from host pid=12345
guest_write=ok
isolation_exit=1
isolation_ls_exit=1
------------------------
PASS: guest read /work/from-host.txt (RW: read)
PASS: host sees /work/from-guest.txt = [from guest uptime=0.07] (RW: write)
PASS: cat /opt/homebrew/Cellar in guest -> exit=1 (isolation: invisible)
PASS: ls /opt/homebrew in guest -> exit=1 (isolation: invisible)
ALL PASS (virtio-fs round-trip + isolation)
```

## Files

| File | Purpose |
|---|---|
| `hello-virtfs.c` | Host binary: ctx + rootfs + `krun_add_virtiofs("agentwork", workdir)` + guest shell that mounts, reads, writes, and probes isolation. |
| `Makefile` | All targets above. |
| `verify.sh` | Round-trip + isolation assertions (called by `make verify`). |
| `bench.sh` | 10× boot timing, same format as `../bench.sh`. |
| `.gitignore` | Built `hello-virtfs` + ephemeral `workdir/`. |

## Caveats

- **No uid mapping.** Files the guest writes appear on the host owned by
  the host user (not the guest's uid). libkrun 1.18 does not expose
  virtiofsd's `uid_map` argument; the in-process virtiofsd uses identity
  mapping. For agentjail proper this is fine for a single-user
  workstation but should be revisited if we ever multiplex agents under
  different host uids. See findings "Things noticed".
- **No DAX window.** `krun_add_virtiofs` (not `krun_add_virtiofs2/3`) is
  the no-DAX variant. Throughput is fine for small files (agent
  source-tree edits); for large blob IO a DAX window via the `_2/_3`
  variants would help.
- **One process per VM.** `krun_start_enter` calls `exit()` and does not
  return on success (same as the base and custom-kernel spikes). Long-running
  agentjail supervisor design is a future concern.

See `tasks/findings/` for the full work log and decisions.
