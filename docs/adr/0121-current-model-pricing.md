# ADR 0121: Current model pricing

**Status:** Accepted

## Context

ADR 0120-bundled-model-pricing chose Gryph's bundled provider instead of a
hand-maintained AgentJail catalog. That remains the right general source, but a
bundled catalog necessarily trails model launches. On 2026-08-01, the installed
Gryph v0.7.0 catalog and Gryph's current `main` catalog did not resolve model
identifiers already emitted by supported agents: `gpt-5.6-sol`,
`gpt-5.6-terra`, `claude-opus-4-8`, and `claude-opus-5`. The estimator silently
reported zero cost for those sessions.

The exact Gryph entry for `claude-opus-4-6` also has zero cache-read and
cache-write rates, while its `@default` variant carries the standard rates.
Claude Code emits the exact identifier, so cache usage was omitted even though
the model appeared priced.

## Decision

Keep Gryph as the general offline catalog and place a small, typed current-model
supplement in front of it. An entry is allowed only when its identifier is
observed from a supported agent and its input, output, cache-read, and
cache-write rates are verified against the model vendor's official pricing.
All other models continue through Gryph; unresolved identifiers remain zero
rather than inheriting a guessed family price.

Rates verified on 2026-08-01:

| Model identifiers | Input / output per MTok | Cache read / write per MTok | Source |
|---|---:|---:|---|
| `gpt-5.6-sol` | $5 / $30 | $0.50 / $6.25 | [OpenAI GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol) |
| `gpt-5.6-terra` | $2.50 / $15 | $0.25 / $3.125 | [OpenAI GPT-5.6 Terra](https://developers.openai.com/api/docs/models/gpt-5.6-terra) |
| `claude-opus-4-6`, `claude-opus-4-8`, `claude-opus-5` | $5 / $25 | $0.50 / $6.25 | [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing) |

OpenAI documents cache writes at 1.25 times uncached input and cache reads at a
90% discount. Claude's transcript exposes one cache-creation total without a
TTL split, so AgentJail applies the standard 5-minute cache-write rate, matching
the existing Gryph `@default` entries.

## Consequences

- Current Claude Code and Codex model identifiers produce non-zero estimates
  immediately instead of waiting for a Gryph release.
- The supplement is deliberately small and source-dated; Gryph remains the
  default and supports the long tail of provider-qualified identifiers.
- Current-model tests cover all four token classes, so a model that prices only
  ordinary input/output cannot masquerade as complete coverage.
- Each supplement change is an external-contract update: verify official vendor
  documentation, record the date here, and remove entries when Gryph provides
  equivalent correct rates.
