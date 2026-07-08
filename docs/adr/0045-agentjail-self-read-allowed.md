# 0045 - agentjail self-protection allows reads (writes stay locked)

Status: Accepted

## Context

The locked rule `file_policy/agentjail_self` (see `agentpolicy/policies/file_policy.rego`)
denied ALL access -- Read, Write, and Edit -- to any path under `~/.agentjail/`.
It is in `locked_rules` (`resolver.rego`), so it cannot be suppressed via
`disabled_rules`. The intent was anti-tamper: an agent must never edit its own
`policy.yaml`, `trusted.yaml`, or the audit DB.

Denying reads as well was defense-in-depth against reconnaissance (an agent could
read the config to learn allowed hosts / disabled rules). In practice it was too
strict: it blocked legitimate debugging and observability. During the Phase 3
deployment it prevented the assistant from reading `policy.yaml` to diagnose why
MCP hosts appeared blocked -- the config turned out to be correct, but the read
deny made that impossible to confirm from inside a session.

The tamper risk is entirely on the WRITE path. Reads cannot modify enforcement
state, and -- critically -- the session bearer token is never on disk; it lives
only in netproxy memory (ADR 0044). So a read of `~/.agentjail` leaks no secret
that would let an agent widen its own egress or self-approve anything.

## Decision

Split the self-protection by operation:

- **Writes stay locked.** `file_policy/agentjail_self` still fires `deny` for
  `Write`/`Edit` under `~/.agentjail/`, still in `locked_rules`, still
  un-disableable. This remains the primary anti-tamper defense.
- **Reads are explicitly allowed.** A new candidate
  `file_policy/agentjail_self_read` fires `allow` for `Read` under
  `~/.agentjail/`. Because `is_agentjail_self` is already a
  `file_specific_matched` clause, the catch-all `file_policy/default` ("ask") is
  suppressed for these paths; the explicit allow therefore resolves a read
  cleanly to `allow` rather than the default `ask`.

This supersedes the read half of the self-protection posture established for the
core self-protection architecture; the write half is unchanged.

## Consequences

- An agent (or the user working through one) can read `policy.yaml`,
  `trusted.yaml`, the audit DB, and logs under `~/.agentjail/` for debugging and
  observability. Writes remain impossible.
- The reconnaissance surface widens slightly: a malicious agent can read the
  enforcement config. This is an accepted trade-off -- the config reveals what is
  allowed/blocked, not how to bypass it, and it holds no bearer secret (tokens
  are memory-only, ADR 0044).
- A cleaner in-session path (render config via a trusted process, request changes
  via approve/deny) is tracked separately as a follow-up (`/agentjail get|update`).
  That remains the preferred long-term UX; this ADR is the pragmatic unblock.
- Tests: `file_policy_test.rego` asserts a Read resolves to
  `file_policy/agentjail_self_read` (allow) while Write/Edit resolve to
  `file_policy/agentjail_self` (deny). The embedded mirror
  (`cmd/agentjail/policies/file_policy.rego`) is kept in parity.

See also: [ADR 0044] (runtime host grants, token-in-memory invariant) and the
trusted in-session config read/update follow-up.

[ADR 0044]: ./0044-runtime-host-grants.md
