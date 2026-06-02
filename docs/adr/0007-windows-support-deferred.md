# 0007 — Windows support: deferred; research and port plan

Status: Proposed (deferred — tracked as a future work item)

## Context

agentjail currently targets **macOS and Linux only**. `install.sh` rejects
other platforms, the release matrix builds only darwin/linux (arm64 + amd64),
and there is no CI lane for Windows. This ADR captures the research done on
2026-05-31 into *what a native-Windows port would actually require*, so that
whoever picks this up later starts from the conclusions rather than re-deriving
them. **No Windows work is committed by this ADR** — it is a parked decision
with a map.

Motivation for looking now: a question about whether hook-based agent tooling
is inherently cross-platform. The short answer is that the **hook mechanism**
(Claude Code's `PreToolUse` system) is cross-platform, but whether a given
tool's hook works on Windows depends on *how that tool implemented it*. We
compared agentjail against `rtk-ai/rtk` (a Rust hook-based CLI proxy) as a
reference point.

### Reference point: how `rtk` behaves on Windows

`rtk` ships a Windows binary (`rtk-x86_64-pc-windows-msvc.zip`) but its
auto-rewrite hook is a **Unix shell script** (`rtk-rewrite.sh`). On native
Windows (PowerShell/cmd) that script cannot run, so rtk falls back to
"CLAUDE.md injection mode" (manual filtering only) and recommends WSL for full
support. The lesson: a POSIX-shell hook script is the thing that breaks a
hook tool on native Windows — not the binary.

### Where agentjail stands today (verified against the code)

**Good — registration is already portable (better than rtk).** Unlike rtk,
agentjail does **not** generate any shell wrapper. `agentjail install --for
claude-code` registers the hook as a *direct binary invocation* and builds all
paths portably:

- The hook command written into `~/.claude/settings.json` is the absolute path
  to the compiled binary, no `sh -c` / `bash` / `.sh` wrapper
  (`cmd/agentjail/install.go:276–283`):
  ```json
  { "matcher": "*", "hooks": [
      { "type": "command", "command": "<home>/.agentjail/bin/agentjail-hook" } ] }
  ```
- Paths use `os.UserHomeDir()` + `filepath.Join` throughout, including the
  settings location (`install.go:561`:
  `filepath.Join(home, ".claude", "settings.json")` → on Windows resolves to
  `C:\Users\<user>\.claude\settings.json`, which is where Claude Code for
  Windows looks).
- No `.sh` generation, no `sh -c`, no shebang emission anywhere in the install
  path. The only `exec.Command` calls are `launchctl` (macOS-only, behind the
  darwin guard).

So the *exact* failure mode that degrades rtk on native Windows does not apply
to agentjail.

**Hard blockers — why it still won't run on native Windows as-is.** agentjail's
architecture is hook → daemon → OPA, and that split is where the Unix
assumptions live:

| # | Blocker | Location | Why it blocks Windows |
|---|---------|----------|------------------------|
| 1 | **Unix domain socket IPC** | `cmd/agentjail-hook/main.go:140` (`net.DialTimeout("unix", …)`) and `cmd/agentjail-daemon/main.go:398` (`net.Listen("unix", …)`) | Go's `"unix"` network type is unsupported on native Windows. The hook would compile and run but **fail to reach the daemon on every call → fail-open**. This is the central blocker. |
| 2 | **`syscall.SIGHUP`** | `cmd/agentjail-daemon/main.go:413` (signal set `SIGTERM, SIGINT, SIGHUP`) | `syscall.SIGHUP` is undefined on `GOOS=windows`; the daemon **won't compile**. |
| 3 | **Install command rejects non-darwin** | `cmd/agentjail/install.go:131–133` (`runtime.GOOS != "darwin"` guard in `installForClaudeCode`) | The installer explicitly refuses to run. (Note: the settings-merge logic itself is already portable; only this guard blocks it.) |
| 4 | **launchd lifecycle** | `install.go:537–597` (`launchctl` load/unload/list + `~/Library/LaunchAgents/` plist) | Daemon supervision is macOS-only; Windows needs a Windows Service or Task Scheduler equivalent. (Linux already needs its own answer here too.) |

**Non-blockers / already safe:**

- The hook reads stdin JSON via `io.ReadAll(os.Stdin)` — portable.
- `cmd/agentjail/logs_sigwinch_unix.go` / `_other.go` are already build-tagged
  so the `!darwin && !linux && …` file covers Windows.
- The `/tmp/agentjail-daemon.sock` fallback path is only reached if
  `os.UserHomeDir()` fails — cosmetic.
- The **shield** (`agentjail-shield`) is a separate matter: it needs an OS
  sandbox primitive (Landlock/`sandbox-exec`); on Windows it would need
  AppContainer / restricted tokens / a minifilter. The current
  `shield_other.go` fallback (`!darwin && !linux`) is a fail-open no-op and even
  uses `syscall.Exec`, which is a non-functional stub on Windows. Shield on
  Windows is **out of scope of even a hook-layer port** and tracked separately.

## Decision

**Defer Windows. Do not build, ship, or test Windows artifacts now.** Keep the
current macOS/Linux-only posture. When Windows is prioritized, scope it as a
**hook-layer port** (the shield stays macOS/Linux), and attack it in this order
— the IPC transport is the first domino and unblocks most of the rest:

1. **Cross-platform IPC transport (the keystone).** Introduce a build-tagged
   transport shim with `listen()` / `dial()` behind a stable interface:
   - `transport_unix.go` (`//go:build !windows`) → Unix domain socket (current
     behavior, no change for macOS/Linux).
   - `transport_windows.go` (`//go:build windows`) → **named pipe**
     (`\\.\pipe\agentjail-daemon`, e.g. via `github.com/Microsoft/go-winio`) or
     TCP loopback (`127.0.0.1:<port>` with a token) if avoiding a new dep.
   Route both `agentjail-hook` and `agentjail-daemon` through it. This also
   improves testability on all platforms. Prefer named pipes over TCP loopback
   for parity with the Unix-socket trust model (no listening TCP port).
2. **Build-tag the daemon signal handling** so `SIGHUP` is Unix-only; on
   Windows handle `os.Interrupt` (and service stop) instead.
3. **Add a Windows branch to `install`.** The settings merge is already
   portable; replace the `runtime.GOOS != "darwin"` guard with per-OS daemon
   bootstrap, and supervise the daemon via a Windows Service / Task Scheduler
   entry instead of launchd.
4. **Release + CI lanes.** Add `windows/amd64` (and `arm64`) to the build
   matrix and a `windows-latest` CI job. Decide installer story: a PowerShell
   `install.ps1` and/or `winget`, since `install.sh` is POSIX-sh.
5. **Sensitive-path patterns.** Audit the file policies for POSIX-isms
   (`/etc/...`, `~/.ssh`, `~/.aws`) and add Windows equivalents
   (`%USERPROFILE%\.ssh`, `%APPDATA%`, credential stores) before claiming
   Windows file protection means anything.
6. **Shield on Windows — separate, later.** Out of scope for the hook port.
   Revisit with AppContainer / restricted-token research if/when there's demand.

Decision criteria for picking this up: real user/enterprise demand for native
Windows (not WSL, which already works like Linux today). Until then, the
recommended Windows path for users is **WSL**.

## Consequences

- **Positive.** The hard part is concentrated in one place — the hook↔daemon
  transport. Because registration and path handling are already portable, the
  port is bounded and well-understood rather than a rewrite. Capturing it now
  means the next attempt starts at step 1, not at investigation.
- **Negative.** Native Windows users get nothing today (WSL works). agentjail
  remains a two-platform tool. The fail-open-on-Windows behavior of the hook
  (blocker #1) means a naive `GOOS=windows` build would *look* installed but
  silently enforce nothing — so we must NOT ship a Windows binary until at
  least the transport (step 1) and signal (step 2) work are done. Shipping a
  fail-open binary would be worse than shipping none.
- **Follow-up.** Tracked in the README roadmap as a future tier item pointing
  here. The shield-on-Windows question is explicitly split out from the
  hook-layer port.
