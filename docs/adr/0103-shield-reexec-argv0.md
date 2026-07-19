# 0103 — Shield tunnel re-exec: dispatch by role, keep the holder alive

Status: Accepted

## Context

The transparent tunnel (`agentjail-shield --tunnel`, ADR 0079 / AGE-148) re-execs
this binary twice: once as the **TUN namespace holder** (`reexecTUNArg`, opens and
configures the TUN inside the new user+net namespace) and once as the **harden
shim** (`reexecHardenArg`, run via `nsenter` to launch the agent inside those
namespaces). Both re-execs used `os.Executable()` to name the binary to run.

Two defects made the tunnel unusable on real installs while passing every
in-repo test (which runs the standalone `cmd/agentjail-shield` binary):

1. **Wrong role after a symlink resolve.** The installed `agentjail-shield` is a
   symlink to the multicall `agentjail` binary, which dispatches on
   `filepath.Base(os.Args[0])` (`cmd/agentjail/main.go`). `os.Executable()`
   *resolves the symlink* to `agentjail`, so the re-exec'd process routed to the
   CLI instead of the shield role. `MaybeRunReexec` never ran, the holder never
   opened the TUN, the parent's `RecvFD` saw EOF, and the shield **silently fell
   back to netproxy**. The standalone dev binary's basename is already
   `agentjail-shield`, so the bug was invisible to `go test` and to a
   dev-built shield — only the shipped symlinked binary hit it.

2. **Holder killed mid-session by a Pdeathsig thread race.** The holder is forked
   with `Pdeathsig: SIGKILL` so it dies with the shield. `Pdeathsig` is delivered
   when the **cloning thread** exits, not the process. `CreateWithTUN` forked on
   an ordinary goroutine, so once `Start()` returned Go could retire that thread
   and the kernel SIGKILLed the holder. The tunnel came up (fd handoff had
   completed) but the *subsequent* `nsenter` to launch the agent failed with
   `cannot open /proc/PID/ns/user: No such file`. This reproduced on a slower
   Ubuntu 24.04 guest and was masked on the faster host, where the thread
   happened to outlive the launch.

A real agent driven through the tunnel in the golden-image VM (a Claude Code
session, not curl) is what surfaced both — exactly the fixture the synthetic
IP-dialing e2e could not be. A third prerequisite is environmental, not a code
bug: Ubuntu 23.10+ ships `kernel.apparmor_restrict_unprivileged_userns=1`, which
blocks the unprivileged userns entirely; the testbed relaxes it in provisioning
and it must be documented as a host setup step.

## Decision

- **Dispatch by role, not by resolved path.** The holder sets `cmd.Args[0] =
  "agentjail-shield"` (`Path` still execs the real file, so multicall dispatch
  reaches `runTUNHelper`). The `nsenter` shim — which cannot set `argv[0]`
  independently — uses `shieldReexecPath()`, which prefers the invocation path
  (`os.Args[0]`, preserving the install symlink) and falls back to
  `os.Executable()` for the standalone binary whose basename already names the
  role. `shieldRoleName` is pinned by a test against the `cmd/agentjail` switch.

- **Fork the holder on a locked, long-lived thread.** `CreateWithTUN` forks
  inside a `runtime.LockOSThread()`'d goroutine that blocks until `Close()`,
  keeping the holder's parent thread (hence Pdeathsig) alive for the namespace
  lifetime. `Namespace.holderDone` releases it on teardown.

## Consequences

- The tunnel works from the shipped symlinked multicall binary, not just the dev
  build; a real agent's HTTPS is decrypted and captured through it.
- One goroutine per live tunnel session is parked on a locked OS thread until the
  namespace closes — a bounded, intended cost of reliable Pdeathsig semantics.
- Regression guard: `reexec_argv0_linux_test.go` pins the role name and the
  path-selection logic. The end-to-end guard is the `tunnel-agent` testbed
  scenario (a real Claude session through `--tunnel --mitm`).
- The AppArmor userns gate remains a documented host prerequisite for Ubuntu
  23.10+; the shield's fallback message already names it.
