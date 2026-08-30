# ADR 0145-install-mcp-discovery: Install MCP discovery

- **Status:** Accepted
- **Date:** 2026-08-30
- **Related:** AGE-295, [ADR 0142-readonly-mcp-inventory](0142-readonly-mcp-inventory.md), [ADR 0143-explicit-mcp-enumeration](0143-explicit-mcp-enumeration.md)

## Context

The configured-server inventory is useful immediately after installation, but
its Tools column is empty until a tool is audited or the user manually runs the
explicit catalog command. That makes a successful install look incomplete even
though the CLI already has a bounded, authenticated `tools/list` implementation.

Enumeration is not observe-only: a configured stdio server command starts, and
a configured HTTP endpoint receives a metadata request. Installation already
represents the user's explicit request to configure and start AgentJail, and its
output can state that this additional catalog step is occurring.

## Decision

Every full or single-agent `agentjail install` whose daemon preamble succeeds
runs MCP catalog discovery immediately afterward. The installer waits
up to two seconds for the control authority and socket, then uses the same typed
service as:

```text
agentjail mcp tool discover
```

The operation requests only `tools/list`; it never sends `tools/call`. Results
are sanitized, bounded, persisted through the singleton event store, and shown
as a compact install summary. Authentication, reachability, timeout, or daemon
readiness failures are non-fatal. Raw errors, configuration values, credentials,
commands, and endpoint details are not printed.

Ordinary inventory Refresh remains passive. The app's Discover Tools action
remains available as an explicit retry when configuration or authentication
changes after installation.

## Consequences

- A new installation normally opens with populated MCP tool counts and names.
- Reinstalling refreshes catalogs without requiring an audited call first.
- Installation may take longer while configured servers answer, and may start
  configured third-party processes or contact configured remote endpoints.
- A broken or unauthenticated MCP server cannot make AgentJail installation
  fail; its bounded status remains available for diagnosis and manual retry.
