# ADR 0142-readonly-mcp-inventory: Read-only MCP inventory

- **Status:** Accepted
- **Date:** 2026-08-27
- **Related:** AGE-295, [ADR 0003-mcp-reverse-proxy](0003-mcp-reverse-proxy.md), [ADR 0141-unified-macos-app](0141-unified-macos-app.md)

## Context

AgentJail already has an MCP gateway that can become the enforcement boundary,
but automatically migrating every existing server into that gateway would make
the first macOS control-panel experience invasive. Users first need an honest
view of what their supported coding agents are configured to use. Discovery must
not change agent startup, execute an untrusted configured command, contact a
remote MCP endpoint, or retain credentials found in configuration.

The three clients use different versioned configuration contracts. Verified on
2026-08-27 against Claude Code 2.1.247 and Codex CLI 0.148.0 installed locally,
plus current vendor documentation:

- Claude Code represents MCP servers under `mcpServers` in JSON. User-scoped
  configuration is stored in `~/.claude.json`; project configuration can also
  use `.mcp.json`. The documented entries support local commands and remote
  HTTP/SSE URLs, including environment and header values.
- Codex stores global MCP configuration in `~/.codex/config.toml` under
  `[mcp_servers.<id>]`; current fields distinguish `command` from `url` and may
  contain environment variables, bearer-token sources, and static headers.
  Project-scoped `.codex/config.toml` is supported for trusted projects.
- Cursor uses an `mcpServers` JSON object in global `~/.cursor/mcp.json` or
  project `.cursor/mcp.json`, with local stdio and remote HTTP/SSE transports.

Sources: [Claude Code MCP documentation](https://docs.anthropic.com/en/docs/claude-code/mcp),
[Codex MCP documentation](https://developers.openai.com/codex/mcp/),
[Codex configuration reference](https://developers.openai.com/codex/config-reference/),
and [Cursor MCP documentation](https://docs.cursor.com/context/model-context-protocol).

## Decision

Phase 1 adds a native read-only MCP inventory to the unified macOS app. A small
typed discovery domain in `AgentjailApprovalCore` owns one explicitly versioned
adapter per client:

- `claude-code-json-v1` reads `~/.claude.json`;
- `codex-toml-v1` reads `~/.codex/config.toml`;
- `cursor-json-v1` reads `~/.cursor/mcp.json`.

The discovery interface exposes only file reads. It has no configuration writer,
process runner, network client, daemon mutation, policy mutation, database, or
telemetry dependency. Opening or refreshing inventory therefore cannot launch a
configured command, perform an MCP health check, contact an endpoint, or change
existing agent behavior.

Adapters decode into typed display records immediately. Raw payloads, arguments,
environment maps, headers, and credentials are not retained in the snapshot.
Local targets show only the sanitized executable basename and an argument count;
argument values stay hidden. Remote targets show only the normalized origin,
with user information, path, query, and fragment removed. Secret-looking names,
commands, or origins are replaced with fixed redaction labels, and all displayed
strings pass through the existing control/bidirectional-text sanitizer.

Server identity is the normalized, redacted server name. Matching identities
across clients are marked as duplicates without retaining a raw command or URL
fingerprint. Each record shows source client, local/remote/unknown kind, redacted
target, configuration status, source label, and adapter version.

Malformed files and unknown entry shapes are non-fatal. The adapter returns a
fixed, secret-free configuration issue beside any other entries it can safely
parse. A missing file means that client has no global configuration; an
unreadable existing file is reported as an issue. Reads require a regular file
and stop at a 2 MiB per-file bound before parsing.

This phase intentionally reads only the three documented global files. The UI
states that project-local configuration and runtime activity are not covered and
does not claim complete traffic visibility. Project discovery, activity
correlation, shadow policy, migration, and enforcement remain later AGE-295
phases.

The inventory may also display a bounded projection of MCP tool names that the
existing AgentJail daemon has already persisted while auditing agent calls. This
projection travels over the authenticated, versioned dashboard control socket;
it is sorted, limited to 64 servers and 128 tools per server, and contains only
sanitized server and tool identifiers. The app labels this data as observed
history. Missing history is **Not observed**, not an empty server declaration.
Reading this projection does not execute configured commands or contact remote
MCP endpoints. Complete live `tools/list` discovery is the separate, explicit
capability in [ADR 0143-explicit-mcp-enumeration](0143-explicit-mcp-enumeration.md),
because stdio discovery starts third-party processes and remote discovery
contacts configured endpoints.

## Consequences

- The app can inventory Claude Code, Codex, and Cursor without becoming a policy
  authority or disturbing existing MCP operation.
- A malformed client configuration remains visible and does not hide valid
  records from other clients.
- Secrets can be present in input fixtures while every public snapshot field
  remains secret-free; the app stores neither source bytes nor raw config data.
- Duplicate detection is conservative and name-based. Different aliases for the
  same endpoint are not merged, while the same normalized name is surfaced for
  human review rather than automatically reconciled.
- Global-only discovery is partial by design and visibly labeled. Expanding to
  project files requires an explicit, bounded project-source contract rather
  than a home-directory crawl.
- Previously audited tool names make the inventory more useful without changing
  Phase 1's no-process-launch and no-network-contact guarantee.
- Explicit enumeration does not weaken that guarantee: it is a separately
  labeled CLI action, while opening and refreshing this inventory remain passive.
