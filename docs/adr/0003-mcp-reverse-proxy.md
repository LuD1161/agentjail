# ADR 0003 — MCP reverse proxy as the strategic MCP control plane

- **Status:** Proposed
- **Date:** 2026-05-23
- **Task:** this ADR; future implementation phases
- **Deciders:** agentjail-core
- **Related:** ADR 0001 (sandbox layer), [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)

## Context

agentjail's current MCP control is **hook-based** and operates only on
`tool_name` at the PreToolUse event:

- `mcp_policy.rego`: allowlist by server name (`mcp__filesystem__*`); blocklist on patterns (`*stripe*`, `*payment*`).
- Per-tool MCP gating (this wave): adds per-tool granularity within an allowed server (`mcp.servers["filesystem"].allowed_tools: ["read_file"]`).

This is the right MVP layer. But it has fundamental limits:

1. **Argument-blind.** When the hook fires, we see `tool_name = "mcp__filesystem__read_file"` and the JSON `tool_input = {"path": "/etc/passwd"}`. Our `file_policy.rego` does not run on MCP calls — it only matches Claude's native `Write`/`Edit`/`Read` tools. So an agent can read `/etc/passwd` via `mcp__filesystem__read_file` and bypass file_policy entirely.
2. **Output-blind.** The hook can decide allow/deny *before* the call runs. It cannot see what the MCP server returns. If the agent reads a file containing an AWS key, agentjail has no way to redact the key from the response.
3. **Pattern-match limits.** Detecting "this MCP call is dangerous" requires the agent's intent to be visible in the tool name + raw arguments. Anything that requires deeper semantics (schema validation, cross-arg constraints, response-aware rules) needs a richer interception point.
4. **Schema drift.** Each MCP server defines its own tools and argument schemas. Hand-writing rules for every server doesn't scale.

The strategic question: **where do we eventually do MCP enforcement?**

## Decision

Build **`agentjail-mcp-proxy`** — a thin process that sits between Claude
Code and each configured MCP server, speaking MCP JSON-RPC on both sides.

### Architecture

```
┌──────────────┐   stdio JSON-RPC   ┌────────────────────┐   stdio JSON-RPC   ┌──────────────────────┐
│  Claude Code │ ─────────────────→ │ agentjail-mcp-    │ ─────────────────→ │  real MCP server     │
│              │                     │ proxy              │                     │  (filesystem, fetch, │
│              │ ←───────────────── │                    │ ←───────────────── │   github, ...)       │
└──────────────┘                     └────────┬───────────┘                     └──────────────────────┘
                                              │
                                              │  Unix socket
                                              ▼
                                     ┌────────────────────┐
                                     │ agentjail-daemon  │
                                     │ (OPA policy eval)  │
                                     └────────────────────┘
```

`agentjail install` rewrites the `mcpServers` block of
`~/.claude/settings.json`. Each entry's `command` is replaced by
`agentjail-mcp-proxy`, with the original command/args passed through:

```jsonc
// Before
"mcpServers": {
  "filesystem": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/project"]
  }
}

// After agentjail install
"mcpServers": {
  "filesystem": {
    "command": "/Users/me/.agentjail/bin/agentjail-mcp-proxy",
    "args": [
      "--server-name", "filesystem",
      "--",
      "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/project"
    ]
  }
}
```

Claude launches the proxy thinking it's the MCP server. The proxy launches
the real server as a child with its own stdin/stdout pipes. Every JSON-RPC
frame in either direction passes through the proxy.

### What the proxy can enforce that the hook cannot

| Capability | Hook (today) | Proxy (Level 4) |
|---|---|---|
| Allowlist server by name | ✅ | ✅ |
| Allowlist tool within server | ✅ | ✅ |
| Validate tool **arguments** against rules (`path` doesn't escape cwd) | ❌ | ✅ |
| Inspect tool **responses** (redact `AKIA*` from file contents) | ❌ | ✅ |
| Enforce against `list_tools` reflection (deny tools we didn't know about) | ❌ | ✅ |
| Cross-call rate limits / session budgets | ❌ | ✅ |
| Schema-driven auto-defaults (use the server's own `inputSchema`) | ❌ | ✅ |
| Bypass-proof at the protocol level | ❌ (agent could call MCP differently) | ✅ (the proxy IS the wire) |

### Why this is the deterministic endgame

- **Sees the actual JSON-RPC frame**, not the agent's mediated intent. The
  proxy reads exactly what Claude wrote and exactly what the server returned.
- **Output-aware.** A write tool's return is uninteresting; a read tool's
  return is the data being exfiltrated. Only the proxy is in a position to
  inspect and redact it.
- **Schema-driven.** When the proxy passes `list_tools` through, it caches
  the response and uses each tool's `inputSchema` to validate subsequent
  calls without per-server hand-written rules.
- **Bypass-proof.** Claude literally talks to our proxy. There is no
  alternate path to the real MCP server — the original `command` is no
  longer in the settings file.

## Consequences

**Positive:**

- Deterministic MCP control: argument validation, response redaction,
  schema-driven defaults all become possible in one place.
- Composable with the existing stack: proxy still calls `agentjail-daemon`
  for policy eval, so all rules live in one place (OPA Rego).
- Single point of audit: every MCP frame is logged.
- Enables real safety stories: "your agent can call the filesystem MCP, but
  it can't read /etc, and any response containing an AKIA-prefixed string
  is redacted before reaching the agent."

**Negative:**

- One additional process per MCP server. Realistic footprint: ~30 MB resident
  per proxy (Go binary + minimal goroutines). Negligible on a dev laptop.
- Per-call latency: ~1-3 ms round-trip (two extra hops through pipes + one
  daemon RPC). Negligible relative to MCP server's own work (often 100+ ms).
- `agentjail install` becomes more invasive: it must rewrite `mcpServers`
  in `~/.claude/settings.json` without clobbering non-MCP entries, and
  `agentjail uninstall` must restore them exactly.
- Risk of subtle breakage with unusual MCP servers — anything that uses
  non-JSON-RPC framing, binary streams, or out-of-band signaling would
  break. We accept this; commit to the protocol-compliant subset.

**Open questions** (must be addressed before implementation):

1. **Stateful sessions.** Some MCP servers expose stateful tools (e.g.
   long-lived database connections via subscription primitives). How does
   the proxy survive its own restart without dropping client state? Probably
   answer: it doesn't — restart kills sessions, just like restarting any
   MCP server today.
2. **Response redaction policy.** What's the redaction language? Reuse OPA
   (Rego rules that take the response as `input`)? A simple regex blocklist?
   A combination?
3. **`settings.json` rewrite safety.** Atomic write-with-backup before each
   rewrite. `uninstall --for claude-code` must reliably restore. Need a
   test that simulates a partial install (proxy installed but original
   command lost) and recovers.
4. **MCP protocol version drift.** MCP is evolving. The proxy needs to
   handle unknown message types by pass-through (don't drop) and log them
   for visibility. We pin a minimum supported MCP protocol version.

## Implementation phases (sketch, not committed yet)

| Phase | What | Rough effort |
|---|---|---|
| Prototype | Prototype proxy: stdio JSON-RPC speak-through, no policy | 1 week |
| Install rewrite | `agentjail install` rewrites `mcpServers` with backup/restore | 1 day |
| Policy eval | Proxy → daemon RPC for policy eval; deny path returns MCP error | 3 days |
| Response redaction | Response redaction (regex blocklist as MVP, OPA-based later) | 1 week |
| Schema defaults | Schema-driven auto-defaults from cached `list_tools` | 1 week |

Total ~3–4 weeks. Not MVP-critical. This ADR commits to the *direction* so
the team doesn't paint itself into a corner with hook-only MCP rules.

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Stay at Level 1 (per-tool name allowlist forever) | Can't catch argument-level abuses (read `/etc/passwd` via filesystem MCP); can't redact responses |
| Modify each MCP server to embed agentjail checks | Server fragmentation; no leverage; every new MCP server needs work |
| Patch Claude Code itself to gate MCP calls | Out of our control; Claude updates would re-disable; doesn't generalize to Codex/Cursor |
| Use OS-level filtering (sandbox-exec on the MCP server process) | Coarse — sees syscalls, not MCP frames; can't redact response content; same Tier-1/2 boundary as shield |
| Run a MITM HTTP proxy in front of MCP | MCP is JSON-RPC over stdio, not HTTP, for most servers; doesn't apply |
