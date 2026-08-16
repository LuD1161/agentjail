# ADR 0139 — canonical SSH temp

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** agentjail-core
- **Supersedes:** the lexical-only temp cleanup in [ADR 0126-session-ssh-bootstrap](0126-session-ssh-bootstrap.md)
- **Related:** [ADR 0124-explicit-ssh-delegation](0124-explicit-ssh-delegation.md)

## Context

ADR 0124-explicit-ssh-delegation requires an absolute, owned, live Unix socket
with no symlink component. ADR 0126-session-ssh-bootstrap lexically cleaned
`TMPDIR` before starting session-only OpenSSH, primarily to remove a trailing
separator. On macOS, lexical cleaning preserves the system `/var` symlink.
OpenSSH then derived `SSH_AUTH_SOCK` beneath `/var/...`; the shield correctly
rejected that path after the user had loaded a key.

Allowing symlink components in the consumer would weaken the capability
validator for every inherited agent. The defect is instead at the trusted
session-agent producer: it can hand OpenSSH the canonical temp root before any
socket exists.

The behavior was verified on 2026-08-15 with macOS 26.2 and OpenSSH 10.0p2. A
real symlink test reproduces the distinction that the previous path-shaped unit
test missed.

## Decision

Canonicalize a non-empty `TMPDIR` with `filepath.EvalSymlinks` only in the
environment used to start AgentJail's session-only OpenSSH agent. If resolution
fails, retain the lexically cleaned spelling; the shield will still fail closed
if OpenSSH produces a socket path containing a symlink.

Do not rewrite an ambient `SSH_AUTH_SOCK`. Do not relax the shared socket
validator, ownership check, Unix-socket check, control-path exclusion, or
launch-time protocol probe.

## Consequences

- AgentJail-created session agents use canonical `/private/var/...` socket
  spellings on macOS and pass the existing validator.
- Inherited, stale, attacker-selected, and symlinked agent paths remain denied.
- Canonicalization changes only the producer's temporary environment; the
  user's shell environment and global OpenSSH configuration are unchanged.
- Tests must create and resolve a real symlink rather than assert only lexical
  string cleanup.
