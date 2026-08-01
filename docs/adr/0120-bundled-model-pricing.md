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

## Consequences

- Cost reporting works offline and shares Gryph's model matching and catalog.
- Gryph attribution ships in `NOTICE`; its license is reproduced in
  `THIRD_PARTY_LICENSES`.
- The CLI and local UI use one typed cost report contract.
- Gryph becomes an OSS runtime dependency, so `THIRD_PARTY_LICENSES` must be
  regenerated whenever its version changes.
- New catalog data requires an AgentJail dependency update; it is not fetched
  dynamically at runtime.
