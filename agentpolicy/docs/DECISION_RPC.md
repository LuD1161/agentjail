# Decision RPC — `agentpolicy/api/decision/v1`

This document covers two related but distinct layers:

1. **[Hook layer](#hook-layer-claude-code-preetooluse)** — the JSON Claude Code
   (and other agents) writes to the hook binary's stdin and reads back from its
   stdout. This is what the coding agent sees.
2. **[Daemon RPC layer](#daemon-rpc-layer-unix-socket)** — the newline-delimited
   JSON that `agentjail-hook` sends over a Unix socket to `agentjail-daemon`,
   which holds the OPA engine warm. This is the internal contract between PEPs
   and the daemon.

---

## Hook layer (Claude Code `PreToolUse`)

### Overview

When Claude Code is configured with an `agentjail-hook` entry in
`~/.claude/settings.json`, it spawns the hook binary on every tool call **before
the tool executes**. The hook has < 50 ms to respond. Exit code and stdout
together determine what the agent does next.

```
Claude Code
  │  (spawns hook binary, writes JSON to stdin)
  ▼
agentjail-hook  (< 1 ms round-trip overhead)
  │  (forwards over Unix socket to daemon)
  ▼
agentjail-daemon  (holds OPA engine warm)
  │  (evaluates Rego, returns action)
  ▼
agentjail-hook  (writes JSON to stdout, exits 0 or 2)
  │
  ▼
Claude Code  (reads stdout, proceeds or blocks)
```

### Hook input (Claude Code → hook binary stdin)

Claude Code writes one JSON object to the hook's stdin:

```jsonc
{
  "hook_event_name": "PreToolUse",   // always "PreToolUse" for this hook
  "tool_name":       "Bash",         // "Bash" | "Write" | "Edit" | "Read" | MCP tool name
  "tool_input":      {               // tool-specific payload
    "command": "rm -rf /tmp/foo"
  },
  "session_id":      "sess-abc123",  // Claude Code session identifier
  "cwd":             "/Users/dev/project"
}
```

`tool_input` schema varies by tool:

| `tool_name` | Key fields in `tool_input` |
|---|---|
| `Bash` | `command: string` |
| `Write` | `file_path: string`, `content: string` |
| `Edit` | `file_path: string`, `old_string: string`, `new_string: string` |
| `Read` | `file_path: string` |
| `mcp__<server>__<tool>` | MCP-tool-specific fields |

### Engine input (normalized `policy.Input`)

`agentjail-hook` normalizes the hook JSON into a `policy.Input` before
forwarding to the daemon. The mapping is:

| Hook field | `policy.Input` field | Notes |
|---|---|---|
| `tool_name == "Bash"` + `tool_input.command` | `hook="exec"`, `program`, `flags`, `argv_raw`, `paths_resolved` | Shell command parsed into argv |
| `tool_name == "Write"` / `"Edit"` | `hook="file"`, `op="write"`, `path=tool_input.file_path` | |
| `tool_name == "Read"` | `hook="file"`, `op="read"`, `path=tool_input.file_path` | |
| `tool_name` starts with `"mcp__"` | `hook="http"`, `host=<mcp-server-uri>` | MCP server URI extracted |
| `session_id` | `context["session_id"]` | |
| `cwd` | `cwd` + `context["cwd"]` | |

The daemon also injects `context["home"]` from the OS environment before
handing the `Input` to the Rego engine.

### Decision output (`policy.Decision`)

The OPA engine returns:

```go
type Decision struct {
    Action string `json:"action"`          // "allow" | "deny" | "ask"
    RuleID string `json:"rule_id,omitempty"` // e.g. "no-recursive-delete-of-protected-paths"
}
```

### Hook response (hook binary stdout → Claude Code)

The hook binary writes one JSON object to stdout and then exits:

**Allow** (exit 0, no stdout required — Claude Code proceeds):
```jsonc
// stdout may be empty on allow; Claude Code proceeds.
```

**Deny** (exit 0 with JSON, or exit 2):
```jsonc
{
  "hookSpecificOutput": {
    "hookEventName":          "PreToolUse",
    "permissionDecision":     "deny",
    "permissionDecisionReason": "rm -rf outside project dir is blocked by file_policy"
  }
}
```

**Ask** (exit 0 with JSON — Claude Code pauses and waits for approval):
```jsonc
{
  "hookSpecificOutput": {
    "hookEventName":          "PreToolUse",
    "permissionDecision":     "ask",
    "permissionDecisionReason": "Writing to .env file requires approval"
  }
}
```

### Exit code semantics

| Exit code | Claude Code behaviour |
|---|---|
| `0` | Parse stdout as JSON; if `permissionDecision` is `"deny"` or `"ask"` act accordingly; otherwise proceed. |
| `2` | **Block immediately.** Claude Code does not read stdout. Emit a hard block. Any content on stderr is shown to the user. |
| Other non-zero | Treated as an error; Claude Code behaviour is agent-version-dependent. agentjail-hook exits `2` on all hard failures. |

Use exit code `2` for fast hard-blocks (timeout, socket failure, obvious deny) to
avoid the JSON parse round-trip. Use exit code `0` + JSON for `ask` verdicts where
the decision reason matters.

### Platform support

| Platform | Hook mechanism | Config file | What is intercepted |
|---|---|---|---|
| Claude Code | `PreToolUse` | `~/.claude/settings.json` | `Bash`, `Write`, `Edit`, `Read`, all MCP tools |
| Codex CLI | `PreToolUse` | `~/.codex/hooks.json` | `Bash`, `apply_patch`, MCP tools |
| Cursor | `preToolUse` + `beforeShellExecution` | `~/.cursor/hooks.json` | All tool types |

All three platforms write the same logical event shape (hook name, tool name,
tool input) but may differ in exact field names. `agentjail-hook` normalizes
each platform's shape into the same `policy.Input` before evaluation.

---

## Daemon RPC layer (Unix socket)

The wire contract between a Policy Enforcement Point (PEP — PATH shim,
runtime hook, mitmproxy addon) and the per-session daemon that fronts
the agentpolicy engine. **Frozen.** Originally shipped in commit
`264eadd` and promoted to a versioned package in .

This document is the authoritative reference for the bytes on the
wire. The Go types live at
[`agentpolicy/api/decision/v1/types.go`](../api/decision/v1/types.go).
Polyglot consumers (Python addon, Node hook, C shim) MUST parse the
same shapes documented here.

---

## Transport

- One Unix-stream socket per session, owned by the daemon.
- Newline-delimited JSON: one `Request` object per line, one `Response`
  object per line.
- A connection may carry many `Request` / `Response` pairs; PEPs MUST
  use the `req_id` field to multiplex.
- A `Request` with empty `req_id` is **fire-and-forget**: the daemon
  emits an audit row and returns no `Response`.
- A `Request` with non-empty `req_id` is **sync**: the daemon writes
  exactly one `Response` echoing the same `req_id`.
- Per-write deadline on the daemon side is 50ms. A wedged PEP cannot
  stall the daemon goroutine.

---

## Request shape (v1)

```jsonc
{
  "hook":    "exec",            // required: "exec" | "http" | "file" | "ping"
  "op":      "GET",             // optional: hook-specific verb
  "pid":     12345,             // optional: emitting process PID
  "ppid":    12344,             // optional: parent PID
  "track":   "node",            // optional: "node" | "native" | "vm"
  "attrs":   { "program": "rm", "args": ["-rf", "/"] },
                                 // optional: hook-specific payload
  "req_id":  "abc"              // optional: enables sync RPC; echo in response
}
```

- `hook` is the only required field for non-ping frames.
- `ping` frames carry only `hook:"ping"` (+ optional `req_id`).
- `attrs` keys per hook are documented per-rule in
  `agentpolicy/policies/`. New keys are additive.

---

## Response shape (v1) — FROZEN

```jsonc
{
  "req_id":  "abc",             // always present; echoes the request
  "action":  "allow",           // required: "allow" | "deny" | "ask"
  "rule_id": "no-rm-rf",        // optional: empty for non-rule paths
  "reason":  "ping"             // optional: documented strings only
}
```

Four fields. No additions to this list without bumping the package
version to v2/. See [Evolution rules](#evolution-rules) below.

### `action` — closed enum

| Value   | Meaning |
|---------|---------|
| `allow` | PEP MAY proceed. |
| `deny`  | PEP MUST abort the operation. |
| `ask`   | Operation requires out-of-band human approval. PEP MUST NOT proceed until a follow-up signal arrives via a separate channel. Treat as `deny` if the PEP cannot suspend the operation. |

Adding a value (e.g. `redact`, `delay`) is a v2 break.

### `reason` — documented strings

When `rule_id` is non-empty, it carries the authoritative
explanation. `reason` is populated only on non-rule paths:

| Value             | When the daemon emits it |
|-------------------|--------------------------|
| `ping`            | Ping liveness probe answered `allow`. |
| `policy disabled` | Daemon has no engine loaded; default `allow`. |
| `eval_error`      | Engine returned an error; fail-open `allow`. |
| `no_rule`         | No rule matched; `allow` is the default. |
| *(empty)*         | Verdict is `deny`/`ask`; see `rule_id`. |

New reasons that follow the existing pattern (free-form
machine-readable lowercase, snake_case or space-separated) may be
added without a version bump — `reason` is a string, not an enum.

---

## Example flows

### Fire-and-forget audit

```
PEP   → daemon  : {"hook":"exec","pid":42,"track":"native","attrs":{"program":"ls"}}
PEP   ← daemon  : (nothing — audit row emitted internally)
```

### Sync exec decision

```
PEP   → daemon  : {"hook":"exec","pid":42,"track":"native","attrs":{"program":"rm","args":["-rf","/"]},"req_id":"abc"}
PEP   ← daemon  : {"req_id":"abc","action":"deny","rule_id":"no-rm-rf"}
```

### Ping liveness

```
PEP   → daemon  : {"hook":"ping","req_id":"ping-1"}
PEP   ← daemon  : {"req_id":"ping-1","action":"allow","reason":"ping"}
```

### Policy disabled

```
PEP   → daemon  : {"hook":"http","attrs":{"host":"example.com"},"req_id":"r1"}
PEP   ← daemon  : {"req_id":"r1","action":"allow","reason":"policy disabled"}
```

---

## Evolution rules

We borrow two disciplines verbatim:

1. **Protobuf field-number reuse rule** — once a field name + JSON tag
   is shipped, it is permanent for the life of the version. We never
   reuse a name, never change a type, never repurpose the semantics.
   ([Protobuf field-deprecation guidance][proto].)
2. **Kubernetes API versioning** — `v1`, `v1beta1`, `v2` are sibling
   packages; you migrate consumers by adding the new import path, not
   by mutating the old one. The old version stays buildable
   indefinitely so two clients on different versions can coexist.
   ([Kubernetes API change conventions][k8s].)

### What is allowed without a version bump

- **Add a new optional `Request` field** that older daemons can ignore
  safely (zero value is meaningful). Example: a new `attrs` key.
- **Add a new `reason` string** (free-form field; closed enum on
  `action` is the only enum-shaped value in v1).
- **Add new rule IDs** — `rule_id` is a free-form identifier the
  engine controls.

### What requires v2

- **Removing or renaming any `Response` field** (`req_id`, `action`,
  `rule_id`, `reason`).
- **Removing or renaming any documented `Request` field.**
- **Adding a new `action` value** (`allow`/`deny`/`ask` is a closed
  enum).
- **Changing a field's type** (e.g. `rule_id` from string to object).
- **Tightening a previously-optional field to required.**
- **Adding a required field.**

### How to add v2 if ever needed

1. Create `agentpolicy/api/decision/v2/` with the new types. Do NOT
   touch v1.
2. Document the diff at the top of the new package + in
   `agentpolicy/docs/DECISION_RPC.md` (this doc grows a "v2" section
   below the v1 section; do not delete the v1 section).
3. Daemon learns the new shape behind a per-connection
   capability-negotiation handshake (Kubernetes uses `Accept:
   application/json;v=v2`; we can put a `version` field on the first
   frame). v1 PEPs keep working unmodified.
4. Each PEP migrates on its own schedule. Plan a deprecation window of
   at least one release cycle before considering v1 retirement.
5. v1 retirement is its own task, gated on observability data showing
   no remaining v1 traffic.

---

## What this contract is NOT

- **Not the engine input shape.** The internal
  [`agentpolicy/internal/policy.Input`][input] carries far more
  fields (Cerbos-shape principal/resource/action, flat legacy
  program/host/path, evaluator context). That type may evolve
  freely; this contract is the stable boundary.
- **Not the audit-event schema.** Audit events have their own
  shape (see [`docs/AUDIT_EVENT_SCHEMA.md`](../../docs/AUDIT_EVENT_SCHEMA.md)).
- **Not a cred-issuance protocol.** Op-specific payloads (e.g.
  delivering a Postgres URL) MUST be new versioned messages under a
  new package, not extensions to `Response`.

---

## Citations

- [proto]: Protobuf — *Updating a Message Type*, the "Do not reuse a
  field number" rule.
  https://protobuf.dev/programming-guides/proto3/#updating
- [k8s]: Kubernetes — *Changing the API* and *API Versioning*.
  https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api_changes.md
- Commit `264eadd` — the original sync decision RPC implementation
  whose wire shape this package promotes to a frozen v1.

[input]: ../internal/policy/policy.go
