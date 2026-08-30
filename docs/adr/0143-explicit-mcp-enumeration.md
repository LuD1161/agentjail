# ADR 0143-explicit-mcp-enumeration: Explicit MCP enumeration

- **Status:** Accepted
- **Date:** 2026-08-30
- **Related:** AGE-295, [ADR 0003-mcp-reverse-proxy](0003-mcp-reverse-proxy.md), [ADR 0142-readonly-mcp-inventory](0142-readonly-mcp-inventory.md)

## Context

The read-only inventory in ADR 0142 can show configured servers and tools that
AgentJail has already audited, but it cannot know a server's complete catalog
before a call occurs. MCP defines `tools/list` for that purpose, including
cursor pagination. Enumerating a local stdio server necessarily starts its
configured command; enumerating a remote server necessarily contacts its
endpoint and may use credentials named in configuration. Treating that as a
normal inventory refresh would violate Phase 1's no-launch, no-network boundary.

The contract was verified on 2026-08-30 against the installed Codex CLI's
`codex mcp list --json`, the current Codex config schema, and the MCP tools and
transport specifications. Codex supports stdio `command`, `args`, and `env`,
plus streamable-HTTP `url`, bearer-token environment variables, static headers,
and environment-sourced headers. MCP `tools/list` responses may be paginated,
and Streamable HTTP may return JSON or server-sent events.

Sources: [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools),
[MCP transports specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[Codex MCP configuration source](https://github.com/openai/codex/blob/main/codex-rs/config/src/mcp_edit.rs),
and [Codex config schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json).

## Decision

Live enumeration is an explicit CLI capability:

```text
agentjail mcp tool discover [--json]
```

The macOS app is a wrapper around the versioned JSON form. It presents a clear
confirmation before invoking the bundled CLI. Ordinary inventory **Refresh**
continues to read configuration metadata and persisted observations only.

The CLI authenticates to the daemon control socket. The daemon owns the live
operation so one single-flight service can bound work, persist results through
the singleton `store.EventStore`, and audit start, completion, and failure. A
shielded agent cannot read the control token and therefore cannot use discovery
to launch configured MCP processes outside its sandbox.

The discovery adapter:

- reads typed connection configuration for Claude Code, Codex, and Cursor;
- starts configured stdio commands with ambient credential variables removed,
  then applies only that server's declared environment;
- contacts only configured remote URLs and applies only configured headers or
  explicitly named environment values;
- negotiates MCP, sends `tools/list`, follows bounded cursor pagination, and
  never sends `tools/call`;
- supports JSON and SSE Streamable HTTP responses, session IDs, and negotiated
  protocol headers;
- sorts, sanitizes, and bounds the control response to 64 servers and 128 tool
  names per server;
- persists server/tool identifiers with source `live`, plus each server's
  fixed discovery status so app relaunches retain actionable results; and
- returns fixed status values (`connected`, `auth_required`, `unreachable`, or
  `timeout`) without returning process, network, config, or credential errors.

Codex TOML is decoded with `github.com/pelletier/go-toml/v2`. A standards-aware
parser is required because connection-bearing arrays, inline tables, quoted
values, and nested maps cannot be handled safely by the older server-name line
scanner. The dependency stays inside the MCP configuration adapter and is
covered by attribution generation.

## Consequences

- Users can pre-populate tool catalogs without waiting for calls to happen.
- The CLI is the stable product surface; the native app does not duplicate the
  control-socket protocol or MCP transport implementation.
- Live discovery is intentionally more invasive than Refresh. The explicit CLI
  command remains the manual retry surface; installation invokes it
  automatically as specified by
  [ADR 0145-install-mcp-discovery](0145-install-mcp-discovery.md). A configured
  third-party stdio command runs with its declared config, and a configured
  remote endpoint receives a metadata request.
- Authentication-required and unreachable servers remain visible instead of
  making the whole pass fail.
- Tool descriptions and schemas are not persisted. The policy and UI need exact
  identifiers, while retaining full schemas would expand the local data surface
  without a current enforcement use.
