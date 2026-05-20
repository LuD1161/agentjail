# agentjail

agentjail wraps a coding agent (Claude Code, Codex CLI, Aider, Cursor, …) in
a containment substrate that records every subprocess, file mutation, and
outbound HTTPS request the agent makes — and, with the microVM driver
enabled, enforces hard network and filesystem boundaries the agent cannot
bypass.

**Status:** alpha. The PATH shim, JS runtime hook, and mitmproxy addon are
working. The microVM driver (libkrun + Firecracker) is in progress.

## Why user-space hooks are not enough

PATH shadowing, in-process JS monkey-patching, and mitmproxy addons give
excellent **observability** for cooperative agents. They are not a containment
boundary. An agent that calls binaries by absolute path, compiles native code,
opens `/dev/tcp/host/port`, or `dlopen`s a fresh libc can walk straight past
them.

agentjail's answer is a per-agent microVM. The user-space hooks stay and
provide audit evidence; the VM boundary enforces what the agent can actually
reach.

See [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) for the full
attack-class matrix with evidence from nine adversarial fixtures.

## What it gives you

- One microVM per agent invocation, started in ~100 ms (libkrun) or
  ~150 ms (Firecracker)
- virtio-fs mount scoped to a single workdir — everything else is invisible
  inside the VM
- TAP egress device that funnels all outbound traffic through a transparent
  proxy; raw-TCP blocked by default
- DNS allowlist
- Sync DENY enforcement at three capture points (PATH shim, JS runtime hook,
  mitmproxy) for cooperative-agent capture
- `events.jsonl` audit log of every captured event
- Built-in default-deny baseline policy (overridable by pointing at an
  `agentpolicy` engine)

## What it does NOT do

- Issue credentials. Credential issuance is handled by the credential broker
  (`agentjail-credbroker`, see ADR 0037) — an optional companion layer.
- Store your audit log centrally. `events.jsonl` is written locally under
  `~/.agentjail/sessions/<sid>/`.
- Gate file reads. Only writes, exec, and network are gated. Keeping secrets
  out of the workdir is the defence-in-depth measure for reads.

---

## Install

### macOS

**Requirements:** Xcode Command Line Tools (`xcode-select --install`), Go
1.22 or newer.

The libkrun microVM backend uses Apple's Hypervisor.framework, which is
present on macOS 11+ for both Intel and Apple Silicon.

```sh
git clone https://github.com/LuD1161/agentjail.git
cd agentjail/agentjail/native/shim
make build
```

The shim binary is written to `agentjail/bin/agentjail-shim`.

Optional: install the tool symlinks so the shim intercepts every tool the
agent looks up by name:

```sh
make install-links   # default: ~/.agentjail/shims/
```

### Linux

**Requirements:** GCC or Clang, Go 1.22 or newer, kernel 6.0+ (for the eBPF
LSM path) or KVM enabled (for the Firecracker path).

```sh
git clone https://github.com/LuD1161/agentjail.git
cd agentjail/agentjail/native/shim
make build
```

Firecracker requires `/dev/kvm`. Check with:

```sh
ls -l /dev/kvm
```

If `/dev/kvm` is absent, enable KVM in your hypervisor settings or on your
bare-metal host.

### Binary releases

Pre-built binaries for macOS (arm64, amd64) and Linux (amd64, arm64) are
published on the [GitHub releases page](https://github.com/LuD1161/agentjail/releases).
Download `agentjail-shim-<os>-<arch>`, chmod +x, and put it on your PATH.

---

## Quickstart: wrap claude in 5 lines

```sh
git clone https://github.com/LuD1161/agentjail.git
cd agentjail/agentjail/native/shim && make build && make install-links
export PATH="$HOME/.agentjail/shims:$PATH"
export AGENTJAIL_SOCK=/tmp/agentjail-demo.sock
agentjail-shim claude
```

On the first invocation `agentjail-shim` resolves the real `claude` binary
by walking `$PATH` past the shim directory, fires an exec event to the daemon
socket (if `AGENTJAIL_SOCK` is set), and `execv`s the real binary with the
original arguments. Stdin, stdout, and stderr pass through unchanged.

To enable enforcement (sync DENY at each exec point):

```sh
export AGENTJAIL_ENFORCE=1
agentjail-shim claude
```

In enforce mode the shim sends a `req_id` to the daemon, reads back a JSON
verdict, and exits 126 on `deny` or `ask`. Any socket/connect/read/timeout
error is treated as `deny` (fail-closed).

---

## What it protects against — and what it does not

### User-space tracks (observability, not containment)

The PATH shim, JS runtime hook, and mitmproxy addon together capture the
vast majority of what a cooperative agent does. They are best-effort. A
determined agent can route around any of them:

| Track | What it catches | Blind spots |
|---|---|---|
| PATH shim | Every exec looked up by basename | Absolute-path invocations (`/bin/sh`), `posix_spawn`, raw `execve` from C |
| JS runtime hook | `fs.*`, `child_process.*`, `fetch`, in-process Node/Bun | Direct syscalls, FFI, compiled binaries |
| mitmproxy | All HTTPS through `HTTPS_PROXY` | TLS-pinned clients, `/dev/tcp`, `unset HTTPS_PROXY` |

**If you need real containment, you need the microVM.** The microVM removes
the blind spots by enforcing at the network and filesystem layer regardless of
what the agent does inside the VM.

See the full evidence matrix in [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md).

### microVM boundary (containment)

Once the microVM driver is running:

- The agent's filesystem view is restricted to the mounted workdir.
- All egress goes through the TAP device. Raw TCP is blocked; only the
  in-guest transparent proxy can reach the outside.
- DNS is allowlisted; arbitrary DNS exfiltration is rate-bounded.

Escape requires breaking the hypervisor (libkrun or Firecracker). That is a
much higher bar than bypassing a PATH shim.

### Honest trade-offs

| Concern | Reality |
|---|---|
| User-space shim = containment? | No. It's evidence. A small C helper can bypass basename-only interception by calling `posix_spawn(3)` directly; see `test/adversarial/runtime-hook/posix_spawn/`. |
| microVM = unbreakable? | No. Host compromise owns the VM. Hypervisor escapes are possible. agentjail is defence-in-depth, not a silver bullet. |
| TLS pinning | A pinned client rejects the in-guest MITM cert. The connection attempt is still logged at the TAP. |
| Redactor | Catches plain, base64, URL-encoded credential substrings. Misses hex, gzip, JSON `\uNNNN`, sharded-across-bodies. Revoke-on-session-end is the real defence. |

---

## Configuration

All configuration is via environment variables. None are required for basic
audit mode.

| Variable | Default | Description |
|---|---|---|
| `AGENTJAIL_SOCK` | *(unset)* | Unix socket path to the per-session daemon. If unset, audit events are dropped silently (the shim still exec-forwards). |
| `AGENTJAIL_SESSION_ID` | *(unset)* | Session identifier stamped into every audit event. |
| `AGENTJAIL_SHIM_DIR` | *(unset)* | Directory containing the shim symlinks. Used to skip self when resolving the real binary. Auto-detected if unset. |
| `AGENTJAIL_ENFORCE` | `0` | Set to `1` to enable sync DENY. The shim blocks on the daemon verdict before forwarding the exec. |
| `AGENTJAIL_SHIM_RLIMIT_NPROC` | `0` (off) | Maximum number of child processes the shim may spawn per invocation. `0` means no limit. |
| `AGENTJAIL_SHIM_WALLCLOCK_SECS` | `0` (off) | Wall-clock timeout in seconds. The shim sends `SIGALRM` to itself if the wrapped command exceeds this. `0` means no timeout. |
| `AGENTJAIL_SHIM_VERIFY` | `1` | Set to `0` to skip the shim's self-codesign integrity check (useful for offline diagnosis only). |

---

## Status

- PATH shim, JS runtime hook, mitmproxy addon — working
- Sync DENY enforcement at all three capture points — working
- Substring leakage redactor for outbound HTTPS bodies — working
- Adversarial test suite (nine fixture classes) — working; see `test/adversarial/`
- eslogger tamper-evidence diff tool — working; see `internal/eslogger/`
- microVM driver (libkrun) — in progress; see `research/libkrun-spike/`
- microVM driver (Firecracker) — in progress; see `research/firecracker-spike/`
- virtio-fs workdir scoping — in progress
- TAP egress + DNS allowlist — in progress

---

## Architecture

agentjail is the containment substrate — the sandbox the agent runs inside,
plus the user-space capture tracks that give observability. The policy engine
(`agentpolicy`) sits above it and evaluates Rego rules against captured events.

The three user-space capture tracks:

```
  agent (Claude Code, Codex CLI, …)
        │
        ├── PATH lookup → PATH shim (C binary) → real binary
        │                      │ exec event
        │                      ▼
        ├── Node/Bun APIs  → JS runtime hook → real API
        │                      │ fs/spawn/fetch event
        │                      ▼
        └── HTTPS_PROXY   → mitmproxy addon
                               │ request/response event
                               ▼
                      ~/.agentjail/sessions/<sid>/events.jsonl
```

---

## Building from source

```sh
# PATH shim (C)
cd agentjail/native/shim
make build

# eslogger diff CLI (Go)
cd agentjail
go build ./internal/eslogger/cmd/agentjail-eslogger-diff/

# All Go packages
go build ./...
go test ./...
```

Linux note: `go test ./...` with the seccomp package requires a Linux host.
On macOS the seccomp tests are stubbed and pass cleanly.

---

## Contributing

agentjail is Apache 2.0. The directory structure is:

```
agentjail/
├── native/shim/      # C PATH shim binary
├── runtime/          # Node/Bun in-process hook (hook.js)
├── addons/           # mitmproxy Python addon + tests
├── internal/         # Go packages (eslogger, seccomp, peercred, …)
├── research/         # Spike work (libkrun, Firecracker)
├── test/adversarial/ # Bypass fixture suite
├── test/smoke/       # Per-tool shim smoke tests
└── docs/             # THREAT_MODEL.md, DECISIONS.md, ADRs
```

Fork the repo, open an issue, or send a pull request. For the subagent
contract (task state files, findings format, commit hygiene) see
[`CLAUDE.md`](./CLAUDE.md).
