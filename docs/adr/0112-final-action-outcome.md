# ADR 0112 — Final per-action outcome with the responsible enforcer

## Status
Accepted

## Context

Two independent layers enforce an agent action: the **policy** daemon (before
the tool runs) and the **OS sandbox** (seatbelt/Landlock, at the syscall). The
UI only ever saw the policy verdict. After ADR 0111 the daemon may return
`allow` for a command the sandbox then blocks (`cat ~/.ssh/id_rsa`), so a row
could read "allow" while the kernel actually denied the read — the surfaced
decision was not truthful about what happened.

We want every logged action to carry **one final outcome** and name **who
enforced it** — policy or sandbox — rather than a policy verdict that another
layer silently overrode.

## Decision

Observe the outcome; never predict it.

- **Correlation.** Each tool call carries a stable `ToolUseID` (Claude Code's
  `tool_use_id` when present, else a hash of session+tool+input). Both hook
  phases and the stored decision key on it, so one action is one record.
- **PreToolUse** (unchanged path): the daemon writes the policy verdict.
  `FinalAction`/`Enforcer` seed from it — a policy deny is already final
  (`blocked`/`policy`); an allow is provisional pending the outcome.
- **Outcome hooks:** the adapter first establishes that the tool failed, then
  looks for the sandbox signature — `EPERM` / "Operation not permitted" — in
  that failure. Claude Code uses `PostToolUseFailure`; Codex uses
  `PostToolUse`, but only a structured nonzero status counts as failure
  evidence. Successful output is never reclassified from prose alone. The
  daemon remains the single writer.
- **Final verdict** is the combination: policy-allow + sandbox-EPERM →
  `blocked` by `sandbox`; policy-deny → `blocked` by `policy` (tool never
  ran); both clear → `allowed`. The UI shows the final verdict and the
  responsible enforcer.

`EPERM` is the same tell on macOS seatbelt and Linux Landlock, so this is
cross-platform — no kernel-log tailing, no macOS-only dependency.

Compatibility was reverified on 2026-07-26 against installed Claude Code
`2.1.216`, installed Codex CLI `0.145.0`, the current official Claude Code
[hooks reference](https://code.claude.com/docs/en/hooks), the current official
Codex [hooks documentation](https://learn.chatgpt.com/docs/hooks), and the
`openai/codex` `rust-v0.145.0` source:

- Claude `PostToolUse` is success-only. Failed tools emit
  `PostToolUseFailure` with top-level `error` and `is_interrupt`.
- Codex `PostToolUse` runs for nonzero Bash status, but `tool_response` is
  tool-specific. The 0.145.0 Bash implementations expose formatted/raw output
  without a guaranteed exit-status field. AgentJail therefore declines sandbox
  attribution for those unstructured responses rather than inferring failure
  from text. A future structured nonzero `exit_code` is handled additively.

## Consequences

- No hardcoded rule→layer map and no predicted sandbox verdicts: the sandbox's
  own EPERM is the evidence, tied to the exact action by `ToolUseID`.
- **Claude Code.** The success and failure events share a per-call id, so a
  sandbox failure can be correlated without scanning successful output.
- **Codex.** A structured nonzero exit status can support attribution. Codex
  0.145.0's unstructured Bash response cannot, so those rows remain
  policy-only instead of risking a false sandbox block.
- **Cursor.** Cursor lacks an equivalent post-hook today, so its rows stay
  policy-only and say so — not faked.
- Attribution is signature-based (`EPERM` in the result) at action
  granularity, not a structured per-syscall record. For a Bash command it
  means "this call hit a sandbox denial," which is the outcome a reader cares
  about.
- Claude installation registers `PreToolUse`, `PostToolUse`, and
  `PostToolUseFailure`. Codex registers `PreToolUse`, `PermissionRequest`, and
  `PostToolUse`.
