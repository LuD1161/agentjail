# ADR 0120: Bundled model pricing

**Status:** Accepted

## Context

Agent cost reports combine token usage from local Claude Code transcripts and
OpenCode's database. Converting those token counts to dollars requires a model
price catalog that handles provider-qualified and versioned model identifiers.
A hand-maintained table would duplicate fast-changing data and require bespoke
matching logic. A runtime pricing service would add network availability and a
remote dependency to an otherwise local report.

## Decision

Use [Gryph](https://github.com/safedep/gryph)'s
`github.com/safedep/gryph/pricing` package at v0.7.0 as the model-pricing
provider. AgentJail constructs its bundled provider once and computes costs
locally from input, output, cache-read, and cache-write token totals. Transcript
readers keep only typed usage aggregates; they do not retain conversation
content or send data to Gryph.

Pricing failure is informational: collection reports the error and leaves the
affected computed cost at zero. It does not affect policy or sandbox
enforcement. OpenCode's own non-zero recorded cost remains authoritative.

### External contract verification

On 2026-07-31, the local compatibility check recorded Claude Code 2.1.220,
Codex CLI 0.146.0, and OpenCode 1.17.8. A minimal `agentjail cost --period 1d
--json` read completed with its output discarded; no transcript content was
inspected or retained. The expected OpenCode database was absent locally, so
that source remains an informational unavailable-reader result rather than a
reason to create or write a database.

Codex's current [configuration reference](https://developers.openai.com/codex/config-reference/)
documents the `CODEX_HOME` state location and sessions directory. The official
[protocol source](https://raw.githubusercontent.com/openai/codex/main/codex-rs/protocol/src/protocol.rs)
and maintained examples establish the observed `event_msg` / `token_count` /
`info.total_token_usage` shape. Persisted rollout JSONL is not a stable public
API, so the reader is bounded, tolerant of unknown records, and reports parse
limits without affecting enforcement.

OpenCode's official [session table source](https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/session/session.sql.ts)
is the primary schema reference for its local database. No public, versioned
Claude Code transcript schema was available during this verification; its
reader therefore accepts only the minimal typed usage fields exercised by the
local fixture and treats all other records as opaque.

## Consequences

- Cost reporting works offline and shares Gryph's model matching and catalog.
- Gryph attribution ships in `NOTICE`; its license is reproduced in
  `THIRD_PARTY_LICENSES`.
- The CLI and local UI use one typed cost report contract.
- Gryph becomes an OSS runtime dependency, so `THIRD_PARTY_LICENSES` must be
  regenerated whenever its version changes.
- New catalog data requires an AgentJail dependency update; it is not fetched
  dynamically at runtime.
- Cost readers cap report windows, files, records, and JSONL line size. They
  use a true read-only SQLite URI plus `query_only`, and surface limit or source
  errors as informational partial-report diagnostics.
