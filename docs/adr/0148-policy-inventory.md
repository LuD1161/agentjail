# ADR 0148-policy-inventory: Local policy inventory

- **Status:** Accepted
- **Date:** 2026-08-31
- **Deciders:** agentjail-core
- **Related:** AGE-293, [ADR 0014-user-tunable-policy-surface](0014-user-tunable-policy-surface.md), [ADR 0018-sqlite-local-store](0018-sqlite-local-store.md), [ADR 0141-unified-macos-app](0141-unified-macos-app.md)

## Context

The unified macOS application reports the number of active rules but cannot
show which rules are loaded, what their installed Rego says, or which local
agent sessions produced decisions attributed to them. The source of truth is
split deliberately: active modules and disable configuration live under
`~/.agentjail`, while selected decision evidence lives in the singleton SQLite
store. Reading either source directly from SwiftUI would bypass the CLI and
store boundaries established by ADR 0141 and ADR 0018.

A decision row records only the rule selected by the resolver. It does not
record every Rego candidate OPA considered. Calling those rows "evaluations"
would therefore overstate per-rule coverage.

## Decision

Add a versioned, bounded `agentjail policy list --json` projection and a fourth
persistent macOS destination, **Policies**.

The CLI enumerates installed active `.rego` modules, applies `disabled_rules`,
and extracts literal rule IDs. It reads selected-decision aggregates through one
typed read-only store handle. The projection calls those aggregates **recorded
matches**, keeps exact per-rule totals, and bounds only the lower-level
agent/session breakdown. It returns only a truncated `…/basename` folder label;
full working directories never cross the projection boundary.

Rego is returned once per source module and referenced by filename from each
rule. Sources, modules, strings, rule counts, and session rows all have explicit
limits. The Swift decoder revalidates the version, relationships, sizes, counts,
and source budget before presenting anything. Policy source and match history
remain local and are never sent through anonymous product telemetry.

The Policies page lists active rules only. Default rules sort first, followed by
Bash/command rules, Git rules, and the remaining active set. Search and category
filters do not change the underlying policy state. Selecting a row opens a
read-only detail containing its description, policy-authored static outcomes,
exact match totals, agent/session attribution, and the installed Rego module.
The source viewer provides two-axis scrolling and local Rego syntax coloring;
copying the exact source is an explicit local user action with visible success
feedback. The app does not edit policy or open SQLite.

## Consequences

- Users can inspect the guardrails actually installed without leaving the app.
- The UI does not confuse resolver-selected decisions with every rule OPA
  considered.
- Historical matches for disabled or removed rules remain in SQLite but are not
  presented as active policy.
- A large history may truncate session rows while preserving exact policy,
  agent, and session totals.
- Rego modules containing several rule IDs are transmitted once, avoiding a
  repeated-source payload.

