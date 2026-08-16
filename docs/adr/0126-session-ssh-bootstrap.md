# ADR 0126-session-ssh-bootstrap

**Status:** Accepted; temp-root handling amended by ADR 0139-canonical-ssh-temp

## Context

The standard policy enables Git over SSH, but many terminals do not already
have a usable `SSH_AUTH_SOCK`. Asking users to start an agent and run
`ssh-add` before every coding session makes the default capability appear
broken. Granting the sandbox direct access to private-key files would remove
the boundary the capability is intended to preserve.

AgentJail must not become a private-key or passphrase handler. It also must not
place a long-lived SSH agent in the daemon: that would outlive the coding
session and turn the daemon into a signing intermediary.

OpenSSH 9.2p1 and Git 2.39.5 behavior were verified locally on 2026-08-06. The
`ssh-agent` command form supplies its socket to one child command and exits
after that command; `ssh-add` accepts identity paths and owns its terminal
prompt. `ssh -G` resolves the effective destination configuration without
connecting. These contracts are documented in the current OpenSSH manuals:

- <https://man.openbsd.org/ssh-agent.1>
- <https://man.openbsd.org/ssh-add.1>
- <https://man.openbsd.org/ssh_config.5>

Compatibility was reverified on 2026-08-12 with macOS 26.2 and its installed
OpenSSH 10.0p2. macOS exported its per-user `TMPDIR` with a trailing slash, and
OpenSSH's command mode appended `/ssh-.../agent...` literally, producing a
valid socket spelling with `//` that the shield correctly refused as unclean.
The upstream OpenBSD `ssh-agent(1)` manual was rechecked the same day for the
command-lifetime and `SSH_AUTH_SOCK` contracts; the Apple path spelling was
established by the local compatibility check.

## Decision

For an interactive `agentjail run` whose effective policy enables Git SSH,
the launcher performs a bounded readiness probe before entering the shield. A
ready inherited agent proceeds normally. If the agent is missing or empty and
local SSH identities are discoverable, the launcher offers a default-yes setup
prompt. An explicit `--git-ssh` request offers setup even when identity
discovery finds nothing.

On acceptance, AgentJail uses OpenSSH command mode:

```text
ssh-agent agentjail __ssh-bootstrap --identity <path> -- agentjail-shield ...
```

The hidden bootstrap command invokes native `ssh-add` with the controlling
terminal as stdin, stdout, and stderr. AgentJail does not pipe, capture, audit,
or store the passphrase, key contents, or OpenSSH output. The compact consent
prompt identifies session-only OpenSSH and states that AgentJail never reads
keys or passphrases. Discovered local identity paths are supplied directly to
`ssh-add`; no shell or `eval` is used.

Before that handoff, the launcher resolves Git's configured push remote for
the current branch, falling back to `origin`, and considers only SSH remote
syntax. It passes the original SSH host or alias to `ssh -G` and keeps the ordered,
existing `IdentityFile` paths under `~/.ssh`. Repository-owner names are not
identity evidence: organizations, collaborators, deploy keys, aliases, and
self-hosted forges make that mapping ambiguous.

One effective identity is selected directly. Multiple effective identities,
or multiple discovered identities when no SSH config match exists, produce an
interactive chooser. The first ordered identity is the default; loading all is
an explicit choice, and declining retains the existing automatic/explicit
launch behavior. The chosen absolute paths are passed as typed internal
bootstrap arguments to native `ssh-add`. AgentJail never reads key bytes. A
ready inherited agent is not mutated or pruned.

After `ssh-add` succeeds, the helper replaces itself with the shield. The
shield remains authoritative: it revalidates and probes the newly inherited
socket before delegation. OpenSSH owns the agent lifetime and terminates it
when the shielded coding session ends. The private-key files remain outside
the shield.

The launcher canonicalizes a non-empty `TMPDIR` only in the child environment
used to start AgentJail's session-only OpenSSH agent. This removes both trailing
separators and macOS's system `/var` symlink before OpenSSH derives the socket
path. If canonicalization cannot resolve the directory, the launcher retains
the lexically cleaned spelling and the shield's validator fails closed if
OpenSSH produces a symlinked socket path. The launcher does not rewrite an
ambient `SSH_AUTH_SOCK`; the shield continues to reject inherited socket paths
that are not already clean, absolute, owned, live Unix sockets.

Noninteractive standard launches never prompt and continue without Git SSH.
An explicit `--git-ssh` launch remains fail-closed when no ready agent or
interactive setup is available. Declining automatic setup continues without
delegation; declining explicit setup aborts the launch. `--no-git-ssh` and the
strict policy never offer setup.

Consented PATH shims invoke `agentjail run -- <agent>` rather than entering the
shield directly, so ordinary `codex`, `claude`, and Cursor launches use this
same default-policy and bootstrap path. If the launcher binary is missing but
the shield remains, the shim warns and falls back to the direct shield; if the
shield is missing, ADR 0063-shim-fails-open-uninstall-is-total still applies.

## Consequences

- A normal interactive launch can establish Git SSH without preparatory shell
  commands or exposing private-key files to the coding agent.
- AgentJail handles orchestration but never handles passphrases or key bytes.
- The created SSH agent has the same lifetime as the coding session.
- A repository with multiple local identities delegates one selected identity
  by default instead of whichever account a server accepts first.
- The delegated agent still exposes every loaded identity for unrestricted
  signing within that session; ADR 0124-explicit-ssh-delegation remains the
  capability boundary.
- Hardware-backed, keychain, and custom SSH configurations may still require
  native OpenSSH configuration outside AgentJail.
