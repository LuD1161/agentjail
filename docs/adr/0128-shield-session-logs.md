# ADR 0128: Shield session logs

**Status:** Accepted

## Context

The shield, transparent tunnel, capture gateway, and MITM path share the
process-wide `slog` logger. Its default handler writes to stderr, where routine
network and lifecycle messages corrupt the interactive terminal used by Claude
Code, Codex, and Cursor. The rescue branch redirected this stream into
per-launch files, but that behavior was stranded during the history rewrite.

The public launcher is now `agentjail run -- <agent>`, not a direct shield
invocation. Restoring only the shield flag would make the debugging control
inaccessible through the canonical command pattern.

## Decision

Every normal shield launch opens a structured JSON log under
`~/.agentjail/logs/` before the audit store or OS sandbox. The filename contains
a UTC nanosecond timestamp and PID, the directory is mode `0700`, and each file
is mode `0600`. The process-wide logger writes at Info level to that file, so
tunnel, gateway, MITM, and shield components inherit the sink.

The newest 10 shield session logs are retained. The current file is always
preserved even if clock skew gives another file a later name. Log creation and
retention outcomes are recorded through the unified audit emitter without file
paths.

`--verbose` tees the same structured stream to stderr. Both
`agentjail-shield --verbose -- <agent>` and the canonical
`agentjail run --verbose -- <agent>` accept it. Launch flags remain before the
separator, and every argument after the agent command remains untouched.
Operational errors and explicit user warnings continue to use stderr directly.

## Consequences

- Routine structured diagnostics no longer bleed into the agent TUI.
- Troubleshooting retains a live stderr mode without changing the persisted
  record.
- Session logs may contain network metadata and errors, so they are private to
  the user and bounded to 10 files.
- A log-open failure is observable but does not weaken or block sandbox
  enforcement.
