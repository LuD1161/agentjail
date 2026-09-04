# ADR 0119-command-approval-transport

Status: Accepted

## Context

ADR 0118-codex-approval-broker proved that a Codex `PreToolUse` Bash `ask`
can reach Codex's native approval UI through a fixed execpolicy broker. The
first implementation allowed only two Git-push rule IDs. Other command asks,
including publish, download, AWS-posture, resolver-default, and custom policy
candidates, still became fail-closed denials.

That rule allowlist puts transport policy in the adapter. Every new Bash `ask`
would need a second code change before Codex could present it, even though the
policy engine had already made the typed decision that human approval was
required. The result is the same semantic gap the adapter is meant to close.

Codex CLI `0.146.0` and the current official
[Hooks documentation](https://learn.chatgpt.com/docs/hooks) were verified on
2026-07-31. `PreToolUse` can replace a Bash command only with
`permissionDecision: "allow"` plus `updatedInput.command`; it cannot return an
interactive `ask`. `PermissionRequest` can observe and decide a prompt Codex
already opened, but cannot create one or rewrite its input. The current
[Rules documentation](https://learn.chatgpt.com/docs/agent-configuration/rules)
confirms that an execpolicy `prefix_rule` can produce the prompt and matches an
argument prefix, so the broker must reject every unexpected suffix itself.

Non-Bash tools are a different protocol problem. Replacing arguments for a
file or MCP call does not turn that call into a command that execpolicy can
prompt for, and Codex exposes no hook response that initiates an equivalent
native request.

## Decision

Introduce `codex_shell_approval_v1`. When both hook and daemon advertise this
capability, every Codex `PreToolUse` request with tool `Bash`, a non-empty
command, and an effective AgentJail action of `ask` uses the one-use approval
broker. Eligibility does not depend on the selected rule ID or namespace. Core,
library, AWS-posture, resolver-default, project, and custom policy asks all use
the same transport.

The typed broker operation is `shell-command`. The rewritten input has exactly
this form:

```text
agentjail approval-exec --operation shell-command --challenge <opaque-id> --reason "<bounded explanation>"
```

The parser accepts only that canonical argv shape. The policy-authored reason is
made single-line, bounded to 512 UTF-8 bytes, and shell-escaped before it enters
the broker argv. The operation and exact reason are bound into challenge minting,
prompt observation, and redemption alongside the Codex
session, turn, tool-use correlation, working directory, policy rule, tool-call
epoch, and kernel-verified Codex process ancestry. An operation mismatch,
unexpected argument, replay, expiry, later tool call, stale process chain, or
unverifiable identity burns or rejects the challenge without executing the
original command.

Keep the original command only in daemon memory. The hook shows its bounded,
printable, store-redacted form immediately before the prompt. Broker argv,
structured logs, and audit detail contain no original command; the broker argv
does contain the user-visible reason. Approval
executes the exact in-memory command once from its original working directory,
preserving the broker process's environment and the session's absolute login
shell behavior.

Retain `codex_approval_bridge_v1` and `git-push` as a legacy compatibility
path. A new hook advertises the shell capability first and the legacy
capability second. A new daemon gives shell-command semantics only to the new
capability; an old hook connected to a new daemon remains Git-only, and a new
hook connected to an old daemon can bridge only the old Git rules. Version skew
therefore narrows behavior and never widens it.

Codex non-Bash `ask` decisions remain fail-closed under
ADR 0117-codex-ask-boundary. Generalizing those tools requires a native Codex
initiation mechanism or a separate typed transport that preserves the original
tool's semantics.

## Consequences

Adding or selecting a Bash `ask` policy no longer requires adapter code. The
policy engine owns whether review is required; the Codex adapter owns how that
review is presented. Git push, package publishing, downloads, AWS commands,
unknown Bash operations, and custom Bash asks therefore share one approval
path and the same fail-closed guarantees.

The native prompt still displays the fixed broker command because Codex does
not expose a display-only replacement for the prompt box. AgentJail's preceding
system message carries the redacted original command and clearly labels the
approval request.

The compatibility gate exercises real Codex `0.146.0` approval for both a
built-in Git rule and a previously unknown custom Bash rule. It proves approve,
decline, `approval_policy=never`, and `--ignore-rules` behavior with guest-local
effects instead of external services. Adapter tests cover command, AWS,
resolver, project, and custom namespaces so adding a rule ID cannot become a
transport prerequisite again.

Non-command asks are still not interactive in Codex. Decision records continue
to preserve `policy_action: ask` and the fail-closed translated action so this
protocol limitation stays visible.
