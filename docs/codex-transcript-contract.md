# Codex transcript cost contract

AgentJail's cost reader treats Codex session JSONL as a versioned integration,
not as a stable hook interface. It decodes only metadata, model context, and
token-count records; conversation content and unknown record types are ignored.

Contract verified on 2026-07-31:

- Installed implementation: Codex CLI `0.146.0`.
- Official source: the OpenAI Codex configuration reference documents
  `$CODEX_HOME/sessions` as the transcript store and `history.persistence =
  "none"` as disabling transcript persistence:
  <https://developers.openai.com/codex/config-reference/>.
- Live JSONL: top-level records carry `type`, `payload`, and `timestamp`;
  `session_meta` carries the session and working directory, `turn_context`
  carries the model, and `event_msg`/`token_count` carries cumulative token
  usage.

Token-count events are cumulative snapshots. The reader keeps the snapshot
with the greatest `total_token_usage.total_tokens` for each session instead of
summing snapshots, including when the same session appears in more than one
file. Cached-read and cache-write input tokens are split from ordinary input
tokens before pricing. Missing transcript directories, including persistence
set to `none`, produce an empty result. Malformed lines and future record/event
types are ignored so a non-usage schema addition cannot break reporting.
