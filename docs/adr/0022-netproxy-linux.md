# ADR 0022 — agentjail-netproxy on Linux

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** agentjail-core
- **Related:** [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox), [ADR 0021](0021-landlock-network-rules.md) (Landlock network)

## Context

`agentjail-netproxy` (a localhost HTTPS CONNECT proxy that enforces
`network.allowed_hosts`) was macOS-only.  The Linux shield
(`shield_linux.go`) warned "agentjail-netproxy not supported on Linux yet"
and did not start the proxy.  The netproxy binary itself
(`cmd/agentjail-netproxy/main.go`) is stdlib-only (`net` + `io.Copy`) with
no macOS-specific imports — it was always portable, just not wired up.

With [ADR 0021](0021-landlock-network-rules.md) adding Landlock network
restriction (kernel 6.7+), the Linux shield restricts the agent to TCP
connect on port 9100 only.  Without a netproxy listening on 9100, the agent
cannot make any HTTPS request — the restriction is in place but the
enforcement path is incomplete.

## Decision

Port `agentjail-netproxy` to Linux by wiring it into the Linux shield the
same way as macOS:

1. **Shared helpers extracted**: `findNetproxyBinary()`, `startNetproxy()`,
   `proxyEnvVars()`, `cleanupNetproxy()`, and the `netproxyDefaultAddr`
   constant are moved from `shield_darwin.go` to a new shared `netproxy.go`
   (no build constraint).  Both macOS and Linux use the same code.

2. **Linux shield starts netproxy**: `runShield()` in `shield_linux.go`
   starts the netproxy as a child process before applying Landlock.  The
   netproxy is forked before Landlock restriction, so it has unrestricted
   network access to reach upstream hosts.

3. **Proxy env vars set**: `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY` are
   set to `http://127.0.0.1:9100` in the agent's environment, routing all
   HTTPS traffic through the netproxy.

4. **`os/exec` instead of `unix.Exec`**: the Linux shield now runs the agent
   as a child process via `exec.Command` instead of replacing itself with
   `unix.Exec`.  This keeps the shield process alive as the parent so it
   can:
   - Forward `SIGINT`/`SIGTERM` to the agent (interactive agents receive
     Ctrl-C normally).
   - Kill and reap the netproxy child on agent exit (zombie cleanup).

   The macOS shield continues to use `syscall.Exec` (replacing the process)
   because Seatbelt profiles are applied to the exec'd process, and the
   netproxy child is orphaned (reparented to init).  Linux's `os/exec`
   approach is a better cleanup model.

5. **Landlock inheritance**: Landlock restrictions applied to the shield
   process are inherited by the agent child (Landlock applies to the
   process and all fork/exec descendants).  The netproxy child, started
   before Landlock, is unrestricted.

### Order of operations

```
1. findNetproxyBinary() → locate the proxy binary
2. startNetproxy()       → fork the proxy child (unrestricted)
3. applyLandlock()       → restrict the shield process (inherited by agent)
4. exec.Command(agent)   → run the agent as a child (inherits Landlock)
5. agentCmd.Run()        → wait for the agent to exit
6. cleanupNetproxy()     → SIGTERM + Wait the proxy child (zombie reaped)
```

## Consequences

**Positive:**
- Linux achieves network parity with macOS: per-host HTTPS egress filtering
  via `agentjail-netproxy`.
- Combined with Landlock network rules (ADR 0021, kernel 6.7+), the agent
  is restricted to TCP connect only on port 9100, where the netproxy
  enforces `network.allowed_hosts`.  Direct egress to IMDS, attacker hosts,
  and non-allowlisted services is denied at the kernel level.
- Proper zombie cleanup: the netproxy child is killed and reaped when the
  agent exits, unlike macOS where it is orphaned.
- Signal forwarding: interactive agents (claude, codex) receive SIGINT and
  SIGTERM normally through the shield.

**Negative:**
- The shield process stays alive as the parent of both the agent and
  netproxy.  This is a process-model change from the previous `unix.Exec`
  approach.  The shield itself is restricted by Landlock (can't write to
  arbitrary paths or connect to non-9100 ports), but this is harmless
  because the shield only waits for the agent and kills the netproxy —
  neither operation is restricted by Landlock.
- The `os/exec` approach adds one level of process nesting (shield → agent).
  This does not affect Landlock inheritance or signal delivery.
- Building the netproxy binary is required for the integration test
  (`go build -o ... ./cmd/agentjail-netproxy`).  This adds ~1s to the test
  suite but verifies the full startup → enforcement → cleanup path.

**Implementation notes:**
- `netproxy.go` (shared) contains `findNetproxyBinary`, `startNetproxy`,
  `proxyEnvVars`, `cleanupNetproxy`, and `netproxyDefaultAddr`.
- `shield_darwin.go` no longer defines these (they were moved to the shared
  file).  Unused imports (`path/filepath`, `time`) removed.
- `shield_linux.go` imports `os/exec`, `os/signal`, `syscall` for the new
  child-process management.
- Tests: `TestNetproxyStartAndCleanup` builds the netproxy, starts it,
  verifies it denies a CONNECT to a non-allowlisted host (403), and
  verifies `cleanupNetproxy` reaps the child.  `TestProxyEnvVars` and
  `TestFindNetproxyBinary_*` test the shared helpers.
