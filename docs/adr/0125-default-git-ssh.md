# ADR 0125-default-git-ssh

**Status:** Accepted

## Context

ADR 0124-explicit-ssh-delegation made raw SSH-agent delegation default-deny
because the socket grants signing access to every loaded identity, not a
Git-scoped capability. That security boundary remains true, but requiring users
to understand `SSH_AUTH_SOCK` before routine clone, pull, and push operations
makes the standard local-development posture unnecessarily obscure.

Agent-specific launch forms also make capabilities appear tied to one coding
agent. The shield and its policy are agent-agnostic; Claude, Codex, Cursor, and
future tools must use the same launch contract.

## Decision

The immutable built-in standard policy sets `capabilities.git_ssh: true`. When
the parent environment has a clean, owned, live SSH-agent socket, the shield
delegates it automatically. An absent automatic socket is quiet; a present but
invalid one warns and continues without Git over SSH. An explicit `--git-ssh`
request still fails closed. `--no-git-ssh` disables the capability for one
launch.

When an interactive launch has local SSH identities but no usable agent, the
launcher offers the session-scoped native OpenSSH setup defined by ADR
0126-session-ssh-bootstrap. Noninteractive automatic launches remain quiet.

The canonical syntax is `agentjail run [flags] -- <agent>`. `--git-ssh` and
`--no-git-ssh` are the only Git-over-SSH launch flags. The agent-specific
`agentjail claude` command remains only as a deprecated
compatibility alias and is removed from primary examples.

The strict sample policy sets `capabilities.git_ssh: false`. This is a standing
default, not a protocol-level Git restriction: a human may still opt in for one
launch. Future Git allow/deny policy is a separate enforcement decision.

Every successful automatic or explicit delegation retains the warning, marker,
path-free audit event, validation, and platform limitations from ADR
0124-explicit-ssh-delegation. The friendly capability name must never be
described as repository- or host-scoped.

## Consequences

- Standard local-development sessions support SSH Git without agent-specific
  launch syntax.
- Strict installations and individual launches can remove the capability.
- A stale or absent parent agent does not prevent an otherwise valid standard
  session from launching.
- Interactive users can establish a session agent without giving the sandbox
  access to private-key files.
- The standard posture accepts broad signing delegation for usability. Users
  needing isolation should use the strict policy or a dedicated constrained
  SSH agent.
