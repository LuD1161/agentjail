# ADR 0150-evaluate-only-default: Evaluate-only policy defaults

- **Status:** Accepted
- **Date:** 2026-09-22
- **Related:** AGE-293
- **Supersedes:** the opt-in monitor default and tool-only scope in ADR 0091-monitor-mode-tools

## Context

The product decision is evaluate and log by default on every platform, with
policy enforcement opt-in. The user explicitly retained OS isolation. The old
monitor mode only rendered online tool verdicts as allow; offline hooks and
network pack handlers could still enforce policy decisions independently.

## Decision

The global policy default and omitted-mode merge fallback are `monitor`.
Explicit `enforce` remains an opt-in, including already saved configurations.
The installer writes the shared default on every platform. It does not overwrite
an existing explicit choice. Project overlays cannot change the global mode.

Tool evaluation keeps its existing daemon-side conversion after evaluation and
before adapter translation and persistence. Policy caches retain canonical
verdicts. A deny/ask becomes allow plus `would_action`; no policy approval is
created by the adapter in monitor mode.

Network gateways resolve the same global mode at session creation. The matcher
selects the most restrictive canonical verdict before rendering the effective
action. HTTP/1.1, HTTP/2, initial recognized TCP operations, and subsequent
recognized database operations share that rendering. Network records store
`policy_action=allow` and `would_action=deny|ask` for observed policy matches.
The network store adds an optional column; read-only access to pre-migration
stores treats that field as absent. The pure matcher constructor remains usable
for policy analysis; production gateways use the configured constructor.

A successfully activated monitoring daemon publishes an allow-only fallback
and a monitoring flag. Offline hooks do not enforce the critical rule subset
in that mode. Codex's unavailable-daemon approval gate honors that attested
flag. A missing or old sidecar does not assert monitor mode. Evaluation failures
and daemon absence remain visible through the existing availability reporting.

OS sandbox profiles, egress isolation/allowlists, managed-port recognition
requirements, credential issuance, host-proxy authorization, control-plane
authentication, TLS validation, and forwarding loop guards remain enforced.
Monitor mode does not authorize a new host capability or bypass agent-native
permissions. Kernel-rejected operations cannot be evaluated after the fact.

The native Policies page labels the configured mode, not an attested active
daemon state. An older CLI response without a mode displays unknown. Native
network events carry would-action separately from effective action.

## Consequences

- Fresh installations evaluate and log without policy blocking on macOS and Linux.
- Existing explicit enforcement settings are preserved; absent settings adopt
  the new default when read by the updated code.
- A daemon restart/reload applies tool policy mode; new sessions are needed for
  network mode changes. Already running gateways retain their launch mode.
- OS isolation and authorization may still refuse operations, by design.
- `agentjail monitor` remains a tool-policy report; network matches are recorded
  in the network store and shown in the network view.
- This source change does not install or activate a new daemon or signed app.
