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
- **PostToolUse** (new): the hook reads the tool result, detects the sandbox's
  signature — `EPERM` / "Operation not permitted" — and sends an `Outcome` to
  the daemon under the same `ToolUseID`. If the sandbox denied, the daemon
  updates the record: `FinalAction = blocked`, `Enforcer = sandbox`. The
  daemon (outside the sandbox) remains the single writer.
- **Final verdict** is the combination: policy-allow + sandbox-EPERM →
  `blocked` by `sandbox`; policy-deny → `blocked` by `policy` (tool never
  ran); both clear → `allowed`. The UI shows the final verdict and the
  responsible enforcer.

`EPERM` is the same tell on macOS seatbelt and Linux Landlock, so this is
cross-platform — no kernel-log tailing, no macOS-only dependency.

## Consequences

- No hardcoded rule→layer map and no predicted sandbox verdicts: the sandbox's
  own EPERM is the evidence, tied to the exact action by `ToolUseID`.
- **Claude Code and Codex.** Both expose a per-call id and PostToolUse hook, so
  both can record the sandbox's final outcome. Cursor lacks an equivalent
  post-hook today, so its rows stay policy-only and say so — not faked.
- Attribution is signature-based (`EPERM` in the result) at action
  granularity, not a structured per-syscall record. For a Bash command it
  means "this call hit a sandbox denial," which is the outcome a reader cares
  about.
- Requires registering both PreToolUse and PostToolUse at install.
