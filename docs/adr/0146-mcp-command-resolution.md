# ADR 0146-mcp-command-resolution: MCP command resolution

- **Status:** Accepted
- **Date:** 2026-08-30
- **Related:** AGE-295, [ADR 0143-explicit-mcp-enumeration](0143-explicit-mcp-enumeration.md), [ADR 0145-install-mcp-discovery](0145-install-mcp-discovery.md)

## Context

Configured stdio MCP servers commonly use a bare executable such as `npx`.
Interactive shells extend `PATH` through shell startup files, but the macOS
daemon is started by launchd with a minimal environment. Discovery therefore
worked when invoked in terminal-shaped tests while the installed daemon could
not start the same server. Starting a login shell would execute user startup
code and make resolution nondeterministic.

The scan command also exposed its internal connection struct through JSON. That
struct necessarily contains configured credentials, but public inventory output
must not expose them.

## Decision

Stdio discovery executes the configured program directly. Resolution checks the
daemon's current `PATH`, then a bounded shared set of user toolchain locations,
plus explicit platform directories selected by build tags. macOS includes
Homebrew's Apple Silicon and Intel prefixes. No shell is started and configured
arguments and environment overrides are passed unchanged to the resolved
executable. Stdio startup receives a 15-second deadline; remote transports keep
the five-second deadline.

`agentjail mcp scan --json` serializes a sanitized copy. Argument, environment,
and header values are replaced; URL credentials, query strings, and fragments
are removed; absolute executable and package paths are reduced to basenames.

## Consequences

- Installed discovery can resolve common package runners without depending on
  shell startup files.
- Custom executables remain supported through explicit configured paths.
- A first package-runner startup can take longer without delaying remote-server
  failure bounds.
- JSON inventory retains topology metadata without disclosing credentials or
  private filesystem paths.
