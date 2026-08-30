# ADR 0144-token-cache: Persisted token cache

- **Status:** Accepted
- **Date:** 2026-08-30
- **Related:** [ADR 0141-unified-macos-app](0141-unified-macos-app.md), [ADR 0143-explicit-mcp-enumeration](0143-explicit-mcp-enumeration.md)

## Context

The Overview projection returns audit and session data quickly, but token usage
comes from parsing local Claude Code, Codex, and OpenCode history. The daemon
already computed that work asynchronously and cached it for five minutes in
memory. On every daemon or app restart the first projection was nevertheless
empty and `loading`, so the chart appeared much later than the rest of the
dashboard. Re-reading all 35 days also repeated work for days whose source data
is effectively closed.

Caching raw transcripts or session records would make startup fast at the cost
of duplicating sensitive local content. An app-owned cache would also put data
semantics in the presentation layer and leave CLI/control consumers with the
same cold-start behavior.

## Decision

The daemon's token projector owns a versioned persistent cache at
`~/.agentjail/cache/dashboard-tokens-v1.json`. It stores only the same bounded
aggregates already present in the dashboard projection:

- daily input, output, and cache-token totals;
- per-day, per-agent input, output, and cache-token totals; and
- aggregate per-agent totals and the cache generation time.

It never stores transcript text, prompts, responses, full paths, project names,
session identifiers, model requests, credentials, or error text. The file is
created atomically with mode `0600`; its directory uses `0700`. The decoder is
versioned, size-bounded, and validates counts and non-negative totals. A missing,
malformed, oversized, or unsupported cache is ignored.

At startup, a valid aggregate is loaded synchronously and returned immediately.
If stale, the projection returns those values with status `loading` while one
background refresh runs. Once a prior aggregate exists, refresh re-reads the
current and previous UTC day and merges them with older cached days inside the
rolling 35-day window. The extra day covers sessions that cross midnight. If
all readers fail, the last good aggregate remains available.

## Consequences

- The token chart can render on the first dashboard response after a restart.
- Historical transcript parsing is avoided during normal refreshes; current and
  cross-midnight sessions still converge in the background.
- The cache is a display optimization, not an audit or billing authority. It is
  safe to delete and is rebuilt from local sources.
- A source that retroactively changes data older than the two-day refresh
  window will not appear until the cache is deleted or its version changes.
- The per-day, per-agent aggregate exists only to merge recent refreshes without
  retaining individual session data.
