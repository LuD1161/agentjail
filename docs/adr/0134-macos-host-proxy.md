# ADR 0134 — macOS host proxy

- **Status:** Accepted
- **Date:** 2026-08-13
- **Deciders:** agentjail-core
- **Related:** [ADR 0132-host-proxy-mvp](0132-host-proxy-mvp.md), [ADR 0034-platform-backend-shared-contract](0034-platform-backend-shared-contract.md)

## Context

ADR 0132-host-proxy-mvp deliberately failed closed outside Linux until another
platform implemented and tested the same process-group and authenticated-session
boundary. That made the shared `agentjail proxy` CLI and policy vocabulary visible
on macOS while every approved execution still ended as `unsupported_platform`.

macOS has the same `setpgid(2)` and negative-process-group `kill(2)` primitives
needed by the bounded executor. The daemon already authenticates local Unix peers,
tracks process ancestry, binds approvals to an exact session, executable, argv, cwd,
root, PATH, and broker PID, and emits the host-proxy audit lifecycle without a
Linux-only data model. The missing pieces were the Darwin executor and registration
of Darwin shield launches with that existing session tracker.

Codex CLI 0.147.0 was installed locally. The official OpenAI
[Hooks](https://developers.openai.com/codex/hooks) and
[Rules](https://developers.openai.com/codex/rules) documentation was checked on
2026-08-13: `PreToolUse` can rewrite a Bash call,
`PermissionRequest` runs only when Codex is about to ask for approval, and a
`prefix_rule` with `decision = "prompt"` prompts for each matching invocation.
This preserves the native-approval ordering assumed by ADR
0132-host-proxy-mvp.

## Decision

The host-proxy domain, command policy, proof format, audit events, output bounds,
timeout, environment behavior, and failure semantics remain shared. Linux and
macOS compile one Unix executor that starts the exact absolute executable without a
shell, stdin, or TTY and concurrently captures bounded stdout and stderr. Thin
`_linux.go` and `_darwin.go` adapters configure and kill the child process group;
other platforms continue to return `unsupported_platform`.

Shield launch registration is also shared. Every macOS launch route—including the
Seatbelt path, provider-gateway child path, credential child path, fail-open
fallback, and transparent-tunnel child path—registers the shield PID, canonical
project root, and sanitized PATH through the authenticated control socket before
starting or replacing the agent process. Child-return paths unregister; an exec
failure unregisters before reporting failure. Registration failure remains visible
and fail-closed for host-proxy authority without preventing the underlying shield
session.

The release test uses a real Codex session. It proves a direct sandboxed execution
cannot read a host-only fixture, a proofless direct proxy call has no effect, one
native approval executes the exact helper, rejection creates no effect, shell
bypass is denied, and the audit lifecycle records exactly one redeemed, started,
and completed execution without the fixture value.

## Consequences

- Linux and macOS now share one policy and execution contract; platform drift is
  limited to the process-group primitives.
- macOS can use host configuration and keychain access under the same explicit
  native allow-once boundary as Linux. Environment-only credentials, stdin, TTYs,
  arbitrary shells, and policy-denied clients remain unsupported.
- A missing control token, daemon, session registration, native approval, exact
  ancestry, or Darwin process-group capability fails closed and produces no host
  execution.
- The host proxy remains an accidental-footgun guardrail rather than a containment
  boundary for an approved executable, exactly as scoped in ADR
  0132-host-proxy-mvp.
