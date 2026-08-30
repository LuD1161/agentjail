# ADR 0147-codex-catalog-bridge: Codex catalog bridge

- **Status:** Accepted
- **Date:** 2026-08-30
- **Related:** AGE-295, [ADR 0143-explicit-mcp-enumeration](0143-explicit-mcp-enumeration.md), [ADR 0145-install-mcp-discovery](0145-install-mcp-discovery.md)

## Context

AgentJail's explicit MCP enumeration reconstructs a connection from each
agent's public configuration. That is sufficient for stdio servers and remote
servers whose bearer headers are declared in configuration, but Codex keeps
OAuth sessions in its own credential store. A Codex server can therefore be
connected and expose tools inside Codex while an independent AgentJail HTTP
handshake receives 401 and reports `auth_required`.

Copying Codex's OAuth token into AgentJail would increase credential exposure
and couple AgentJail to private token-storage details. Codex app-server exposes
the authenticated, initialized catalog through `mcpServerStatus/list`, including
tool definitions and bounded cursor pagination. The method does not require a
model turn or a tool invocation.

The contract was verified on 2026-08-30 against locally installed Codex CLI
0.148.0 by generating its TypeScript protocol bindings and running a live
`toolsAndAuthOnly` compatibility check. The live response contained the same
tool counts shown by the Codex TUI. The current primary source documents
[`mcpServerStatus/list`](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md#mcp-server-status) as the configured-server inventory surface.

## Decision

MCP discovery accepts authenticated agent catalogs through a consumer-owned
`AuthenticatedToolCatalog` interface. The Codex implementation:

1. resolves the installed `codex` executable through the same bounded command
   contract used for launchd MCP commands;
2. starts `codex app-server --stdio` with ambient provider credentials removed;
3. initializes the JSONL protocol and requests only
   `mcpServerStatus/list` with `detail: toolsAndAuthOnly`;
4. follows at most 32 pages, accepts at most 256 servers and 2,048 tool names
   per server, and limits each message to 32 MiB;
5. retains only server and tool identifiers plus the fixed connected/auth
   outcome—never schemas, descriptions, credentials, or raw errors; and
6. never sends `turn/start`, `mcpServer/tool/call`, or another executable
   app-server request.

Direct MCP enumeration and authenticated catalogs run concurrently. A Codex
catalog result replaces direct discovery only when the server already exists
in AgentJail's configured inventory and Codex returned an initialized catalog
or an explicit not-logged-in outcome. Missing, unsupported, failed, or older
app-server integrations leave the direct result unchanged.

## Consequences

- Tool counts match the effective Codex session without AgentJail reading or
  persisting Codex OAuth tokens.
- Explicit discovery may still start configured MCP processes or contact their
  endpoints, as already disclosed by ADR 0143-explicit-mcp-enumeration.
- The app-server process adds bounded work to discovery but runs concurrently
  with the existing handshakes and remains within the 50-second CLI deadline.
- A Codex protocol regression degrades to the existing direct behavior instead
  of failing the whole inventory.
- Claude Code or Cursor can implement the same interface if they expose a
  similarly bounded authenticated catalog in the future.
