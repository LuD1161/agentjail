# ADR 0117-codex-ask-boundary

Status: Accepted

## Context

AgentJail's canonical policy action `ask` requires a user-mediated decision.
Codex's `PermissionRequest` hook observes a request that Codex has already
chosen to present; it does not create one. `PreToolUse` cannot return a native
approval decision, and unsupported decision fields cause Codex to continue the
tool call.

The former default-mode git-push bridge deferred `PreToolUse` in the hope that
Codex would subsequently emit `PermissionRequest`. That sequence is not
guaranteed. In particular, an approval policy of `never` cannot present a
native prompt, and a default-mode command may proceed without Codex requesting
one. Deferring an AgentJail `ask` could therefore turn it into an allow.

Verified 2026-07-24 against Codex CLI `0.145.0` and the current official
[Codex Hooks documentation](https://learn.chatgpt.com/docs/hooks):

- `PermissionRequest` is an observation point for Codex's own approval flow.
- `PreToolUse` and `PermissionRequest` support `systemMessage`, but not hook
  output that requests an approval or stops the tool by a structured decision.
- `permission_mode` includes `default`, `acceptEdits`, `plan`, `dontAsk`, and
  `bypassPermissions`; it describes the active Codex mode, not a hook-created
  approval capability.

## Decision

Render every canonical AgentJail `ask` as `deny` at Codex `PreToolUse`, in every
permission mode. Record the canonical `policy_action: ask`, the translated
`effective_action: deny`, the adapter, and the translation reason in the
decision record.

Keep the `PermissionRequest` hook registered. When Codex independently opens a
native request, AgentJail can allow or deny it; a canonical `ask` emits no
decision so Codex preserves its own prompt. This hook cannot be used to turn a
previous PreToolUse policy `ask` into a prompt.

An explicit AgentJail approval broker may be introduced only as a separate
design with authenticated user intent and auditable grants. Until then, a
Codex policy `ask` is fail-closed.

## Consequences

Codex never silently converts an AgentJail confirmation requirement into an
allow. A normal interactive Codex approval still works for decisions Codex
itself requests, but it is not a substitute for the AgentJail `ask` action.
Users receive an explicit denial rather than a misleading promise of a native
prompt.
