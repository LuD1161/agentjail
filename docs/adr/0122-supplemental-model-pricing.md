# ADR 0122-supplemental-model-pricing

Status: Accepted

## Context

ADR 0120-bundled-model-pricing made Gryph v0.7.0 the offline model-price
provider. On 2026-08-02, v0.7.0 was still Gryph's latest release and neither
its released catalog nor its main-branch catalog contained `gpt-5.6-sol` or
`claude-opus-4-8`. AgentJail decoded their token usage but silently priced it
at zero, so historical and current reports showed `$0.00` despite millions of
tokens.

The installed integrations were Claude Code 2.1.220 and Codex CLI 0.146.0.
Local compatibility records confirmed the existing Claude assistant-usage and
Codex cumulative token-count shapes. Current primary pricing sources were
verified on 2026-08-02: OpenAI documents GPT-5.6 Sol, Terra, and Luna input,
cached-input, output, and 1.25x cache-write rates; Anthropic documents Claude
Opus 4.8 input, output, cache-read, and five-minute cache-write rates.

Primary sources:

- <https://developers.openai.com/api/docs/models/gpt-5.6-sol>
- <https://openai.com/index/gpt-5-6/>
- <https://www.anthropic.com/news/claude-opus-4-8>
- <https://www-cdn.anthropic.com/files/4zrzovbb/website/3684c2faafb97418665782cea0001f439f74b1d2.pdf>

## Decision

Keep Gryph's bundled provider as the primary catalog. Add a typed, source-dated
supplemental table only for verified current models absent from the latest
Gryph release: Claude Opus 4.8 and the GPT-5.6 Sol, Terra, and Luna family.
Gryph wins automatically when it resolves a model; the supplemental rate is
consulted only after a catalog miss. Unknown models remain unpriced rather than
being guessed, and reports emit one diagnostic per unknown model so a future
catalog lag cannot silently render token-bearing sessions as `$0.00`.

Cost reports remain derived views. Every CLI or UI request rereads eligible
local sessions and computes cost from their recorded token totals, so adding a
price recalculates historical sessions without a migration or transcript
rewrite. Per-model summaries expose the uncached-input, cache-read,
cache-write, and output totals that contribute to the estimate; showing output
alone makes cache-heavy workloads appear arithmetically inconsistent.

Preserve pricing dimensions present in vendor transcripts. Claude Code's
`cache_creation` object separates five-minute and one-hour writes, which use
different documented rates. Codex's `last_token_usage` supplies the per-request
input size required for GPT-5.6's over-272K input tier. Apply that tier only
when the sum of retained request records matches the final cumulative usage;
otherwise calculate at base rates and emit an explicit diagnostic. A
session-wide cumulative total must never be treated as one oversized request.

## Consequences

- Current Claude Opus 4.8 and GPT-5.6 sessions receive non-zero offline cost
  estimates, including sessions created before this change.
- Gryph remains the broad model-resolution source; the local supplement is
  intentionally small and must cite primary pricing before expansion.
- Pricing estimates without complete per-request detail remain explicitly
  marked base estimates.
- Claude cache TTL pricing and complete Codex request sequences can be
  reconstructed exactly from their current local transcript contracts.
