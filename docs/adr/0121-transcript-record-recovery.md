# ADR 0121-transcript-record-recovery

Status: Accepted

## Context

ADR 0120-bundled-model-pricing bounded local transcript ingestion with a 1 MiB
JSONL record limit. The implementation used `bufio.Scanner`, which stops
permanently when a token exceeds its maximum. Current Claude Code and Codex
transcripts legitimately embed megabyte-scale user and tool output, so one
large content record prevented every later usage snapshot in that file from
being read.

On 2026-08-02, live compatibility checks used Claude Code 2.1.220 and Codex CLI
0.146.0. The affected Claude records were typed `user`; the affected Codex
records were `response_item` tool outputs. Their later assistant-usage and
`event_msg`/`token_count` records retained the established small typed shapes.
Anthropic documents JSONL as one complete JSON object per line, and OpenAI
documents `$CODEX_HOME/sessions` as Codex's transcript location:

- <https://docs.anthropic.com/en/docs/claude-code/sdk>
- <https://developers.openai.com/codex/config-reference/>

## Decision

Replace `bufio.Scanner` with a bounded JSONL reader that retains at most 1 MiB
for one record. If a record exceeds that bound, discard only that record through
its newline and continue with the next one. Keep the existing caps on files,
sessions, period, and retained record bytes.

Malformed records remain opaque and non-fatal. Actual file I/O failures remain
source diagnostics. Tests must place valid usage after the oversized fixture so
they prove delimiter recovery rather than only memory rejection.

## Consequences

- Large content and tool-output records no longer hide later usage records or
  exclude the whole session from cost reports.
- Reader memory remains bounded independently of transcript record size.
- A usage-bearing record larger than 1 MiB would be skipped. Current live
  oversized records were content/tool-output records, while usage snapshots
  remained below the bound.
