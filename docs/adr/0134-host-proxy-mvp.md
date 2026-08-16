# ADR 0134 — Host proxy MVP

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** agentjail-core
- **Related:** AGE-174, [ADR 0118-codex-approval-broker](0118-codex-approval-broker.md), [ADR 0119-command-approval-transport](0119-command-approval-transport.md)

## Context

The immutable Linux shield correctly prevents an agent from starting host-installed
tools outside its executable surface. Some ordinary, read-only CLIs are useful only
with their host configuration or keychain, however. Reconstructing the complete
shield around one additional executable is AGE-274 and is deliberately outside this
MVP.

A same-UID daemon socket request is not approval. Codex's `PreToolUse` hook can
rewrite a Bash command, but it cannot open a prompt. An execpolicy prompt occurs
after that rewrite, and `PermissionRequest` observes the prompt rather than proving
its eventual result. The trustworthy positive artifact is therefore a new broker
process that exists only after Codex approves the managed prompt and whose ancestry
is newer than the observed prompt boundary.

Codex CLI 0.147.0 and the official OpenAI
[hooks](https://learn.chatgpt.com/docs/hooks) and
[rules](https://learn.chatgpt.com/docs/agent-configuration/rules) documentation were
checked on 2026-08-12. The local approval spike confirmed the ordering and rejection
behavior recorded below.

## Decision

On Linux, `agentjail proxy -- <argv...>` is a typed command intent. It is eligible
only from an authenticated shield launch whose control-token registration pins a
canonical session root and sanitized PATH. The daemon resolves the top-level
executable through that PATH, follows symlinks, and denies sensitive clients,
AgentJail control binaries, shells, direct interpreters (including versioned runtime
names), and generic/package-runtime wrappers. Every other executable requires
a native Codex allow-once decision.

The existing approval challenge uses the typed `host-proxy` operation. Prompt
observation arms that challenge and records a fresh process-start boundary. Native
approval starts the fixed `approval-exec` broker; rejection starts no broker. The
daemon verifies and burns the first challenge, then issues a second short-lived,
one-use proof bound to the authenticated session, canonical executable, exact argv,
canonical cwd, registered root and PATH, broker PID, and fresh descendant chain.
The broker preserves its PID while replacing itself with `agentjail proxy`, so a
same-UID direct socket caller cannot redeem the proof. Mismatch, expiry, replay, or
missing ancestry burns or refuses it.

The daemon cannot depend on `/proc/<peer>/cwd`: common Linux ptrace restrictions
deny that read between same-UID sibling processes. Instead, the trusted PID-bound
broker changes to the approved cwd before preserving its PID across `exec`; the
daemon independently resolves the proof-bound cwd from the filesystem and requires
it to remain within the control-token-registered shield root. Caller-supplied cwd
or root values never create authority.

After redemption the daemon repeats executable resolution and policy evaluation,
then directly starts the absolute executable without a shell, stdin, or TTY. It uses
the daemon service environment, captures stdout and stderr concurrently, limits
combined output to 1 MiB, limits runtime to 30 seconds, and kills the Linux process
group on cancellation, timeout, or overflow. Non-Linux executors fail closed until
their process-group behavior is implemented and tested.

Audit records distinguish requested, denied, authorization-redeemed, started, and
completed states. They store only session identifiers, short hashes of the target
and cwd, and structured outcomes; proofs, argv, environment contents, and credential
values are excluded.

The basename/category policy is an accidental-footgun guardrail. It does not defend
against renamed malicious binaries, an approved malicious program, or an allowed
tool that starts helpers. The cwd check constrains only the starting directory; the
approved process runs as the daemon user outside the shield and may access normal
host filesystem, network, configuration, and credentials.

## Consequences

An eligible host CLI can be run once from a shielded Codex session after a visible
native prompt, while direct invocation remains blocked by the immutable shield.
Rejection creates no secondary proof because the broker never starts. Daemon restart
or proof expiry safely invalidates pending work.

The environment is intentionally not an interactive login-shell environment.
Configuration files and OS keychains may work, while environment-only credentials
and interactive programs do not. Output is buffered rather than streamed. macOS,
persistent approvals, arbitrary environment forwarding, credential injection, and
fresh child-sandbox construction remain deferred.
