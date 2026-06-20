# 0019 — Redaction policy for persisted tool inputs

Status: Accepted

## Context

Until now agentjail never persisted the full `tool_input` of a tool call.
The slog `eval` line in `daemon.log` records a `summary` (the command
string truncated to 200 chars, or the file_path) but not the full payload.
`audit.log` records only the rule_id and action, never the payload.

SQLite (ADR 0018) changes this: the `decisions.tool_input_redacted` column
stores the full `tool_input` JSON so `agentjail replay --verbose` can show
what the agent actually tried to do. This is the first time
secret-bearing payloads are persisted to disk by agentjail, so a redaction
policy is required.

The threat model is foot-gun, not adversary (research note §1): the DB is
`0600`, owned by the user, under `~/.agentjail/` (denied to the agent by the
locked `file_policy/agentjail_self` rule). The risk is not exfiltration by
the agent; it is that a *human* inspecting the DB (via `agentjail logs` or
`replay`) accidentally sees a secret that flowed through a tool call — e.g.
`cat ~/.aws/credentials` (the command string would contain the path, but a
tool like an MCP server could echo a credential into `tool_input`), or a
`curl` with `--header "Authorization: Bearer ..."`. Redaction keeps the DB
safe to browse and to share (e.g. attaching `agentjail.db` to a bug report).

## Decision

**The full `tool_input` is persisted, but redacted, before it is written to
SQLite.** Redaction is a one-way transform applied at the store boundary;
the raw `tool_input` is never persisted.

### What is redacted

For every key in the `tool_input` map (recursively, including nested maps
and maps inside slices), if the key name **case-insensitively contains** any
of these substrings, the value is replaced with the literal `"[redacted]"`:

- `secret`
- `key`
- `token`
- `password`
- `cred`

These cover the common credential-bearing key names: `AWS_SECRET_ACCESS_KEY`,
`AWS_ACCESS_KEY_ID`, `AWS_SESSION_TOKEN`, `api_key`, `apiKey`, `auth_token`,
`password`, `passwd`, `credential`, `creds`, `secret_key`, `access_token`.
The substring match is deliberately broad — over-redaction (e.g. `keyword`)
is safe; under-redaction (missing a novel key name) is not. A real secret
under a key like `x_amz_credential` is caught by `cred`; under
`Authorization` it is not caught by the key rule, so callers that place
secrets in header values should also see value-level redaction (below).

### Value truncation

The redacted JSON is truncated to **4096 bytes** (4 KB) with a trailing
`…` if it exceeds that. This bounds the DB row size and prevents a
multi-MB `tool_input` (e.g. a large file write's `content`) from bloating
the store. The first 4 KB is enough to identify what the agent tried; the
full payload is not needed for replay/forensics.

### What is NOT redacted

- File paths, command strings, URLs, MCP tool names, and arguments that do
  not match the key substrings. These are the bulk of `tool_input` and are
  the point of storing it (replay shows what the agent did).
- The `summary` column (already truncated to 200 chars by the daemon, not a
  secret-bearing field).

### Where redaction runs

`internal/store.RedactToolInput(map[string]interface{}) string` is the sole
redactor. It is called in the daemon's async write path, immediately before
the `INSERT`. The raw `tool_input` is not retained in memory beyond the
write. The CLI read path (`agentjail logs`, `replay`) reads the already-
redacted column — it cannot un-redact.

### Limits (acknowledged)

- **Key-based, not value-based.** A secret placed under a key that does not
  match the substrings (e.g. `Authorization`, `X-Custom-Header`) is not
  redacted by the key rule. The foot-gun model rarely sees this (agents pass
  secrets via env or credential files, not via tool_input header keys), and
  the DB is 0600 + agent-unreadable. A future value-based heuristic (detect
  AWS-key-shaped strings, high-entropy blobs) can layer on top without
  changing this policy.
- **Recursive but shallow on values.** A secret buried inside an opaque
  encoded string (base64, JSON-in-a-string) under a redacted key is
  replaced wholesale with `"[redacted]"`, which is correct. Under a
  non-redacted key it survives — the same limit as above.
- **Not tamper-proof.** The DB is a local file; a same-user process can edit
  it. Redaction is a privacy/ergonomics measure for browsing and sharing,
  not a tamper-evidence control (same posture as the existing `audit.log`).

## Consequences

+ The DB is safe to browse via `agentjail logs`/`replay` and safe to attach
  to a bug report — no secret key names leak their values.
+ `replay --verbose` shows the redacted `tool_input`, enough to understand
  what the agent tried without exposing credentials.
+ One redactor at the store boundary — no call site can accidentally persist
  a raw `tool_input`.
+ Over-redaction is safe; the cost is a slightly less informative
  `tool_input` for keys like `keyword` (rare in practice).
- A secret under a non-matching key (`Authorization`) is not redacted. The
  DB remains 0600 + agent-unreadable; value-based redaction is future work.
- Truncation to 4 KB means very large payloads are partially lost. This is
  acceptable for replay/forensics; the full payload is not the goal.
