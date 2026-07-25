# ADR 0114-codex-permission-request

Status: Superseded by 0117-codex-ask-boundary

## Context

AgentJail has one canonical policy vocabulary: `allow`, `ask`, and `deny`.
Codex CLI's `PreToolUse` hook can allow or deny, but its documented
`permissionDecision: "ask"` is unsupported and lets the tool continue. Codex
instead exposes `PermissionRequest` when *Codex itself* is about to request
approval. That event can allow, deny, or emit no decision, in which case
Codex presents its normal approval UI.

Verified 2026-07-24 against Codex CLI `0.145.0` and the current official
[Codex Hooks documentation](https://learn.chatgpt.com/docs/hooks):

- `PermissionRequest` only runs when Codex is already going to ask; it does
  not run for calls that need no Codex approval.
- An `allow` or `deny` response uses
  `hookSpecificOutput.decision.behavior`.
- No matching decision leaves Codex's normal approval flow in place.
- `permissionDecision: "ask"` on `PreToolUse` is unsupported and Codex
  continues the call after reporting the hook failure.

## Decision

Register `PreToolUse`, `PermissionRequest`, and `PostToolUse` for Codex.
Normalize `PermissionRequest` to the canonical `PreToolUse` policy input at
the adapter boundary, so one policy bundle evaluates the same tool identity
and arguments.

For a Codex `PermissionRequest`, render canonical decisions as:

- `allow` → native PermissionRequest allow;
- `deny` → native PermissionRequest deny;
- `ask` → no decision, so Codex's native approval UI remains responsible.

`PreToolUse` remains the enforcement boundary for every action, except one
verified native bridge: `command_policy/confirm-git-push` in Codex's
`permission_mode: "default"`. The adapter defers that exact canonical `ask`
without output so Codex proceeds to `PermissionRequest`, where AgentJail
declines the ask and Codex presents its normal approval UI. Every other
PreToolUse ask, including git push under `dontAsk`, `bypassPermissions`, or a
non-default mode, is denied with an explicit explanation. No AgentJail ask
may silently become an allow.

## Consequences

Codex-native approval now works for ordinary git push in default mode. The
bridge is rule-specific and mode-specific; AgentJail cannot safely present a
native Codex prompt for arbitrary policy asks without a future Codex protocol
feature or a separate, explicitly designed approval broker.
