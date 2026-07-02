# ADR 0040: MCP-derived allowed hosts, mcp-proxy.anthropic.com, and fail-loud on malformed policy

- **Status:** Accepted
- **Date:** 2026-07-01
- **Deciders:** agentjail-core
- **Related:** [ADR 0038](0038-essential-vs-extended-allowed-hosts.md) (essential vs. extended allowed_hosts), [ADR 0039](0039-complete-shared-sandbox-contract.md) (shared sandbox contract)

## Context

ADR 0038 split `network.allowed_hosts` into an essential (non-removable)
tier and an extended (editable) tier, merged by `EffectiveAllowedHosts`.
Three problems remained after that work:

1. **Curated `allowed_hosts` silently breaks allowed MCP servers.** A user
   who trims `Network.AllowedHosts` down to a small curated list (e.g. only
   `github.com` and `registry.npmjs.org`) keeps their `mcp.allowed` entries
   working at the MCP gate (`mcp_policy.rego`), but the underlying network
   call to that MCP server's host is now blocked by netproxy -- the MCP call
   passes the tool-level check and then times out or 403s at the network
   layer. There was no link between "this MCP server is allowed" and "its
   host is reachable."

2. **claude.ai connectors need a proxy host that wasn't essential.**
   claude.ai's hosted MCP connectors (Gmail, Google Calendar, Google Drive,
   typefully, and others) route their MCP traffic through
   `mcp-proxy.anthropic.com`. It was not in `EssentialAllowedHosts()`, so
   those connectors silently broke under the shield even with `claude.ai`
   itself reachable.

3. **A present-but-malformed `policy.yaml` silently fell back to permissive
   defaults.** `agentjail-shield`'s `main.go` and
   `agentjail-netproxy`'s `loadPolicy`/initial load both treated "file
   doesn't parse" the same as "file doesn't exist" -- swallowing the error
   and using `config.Default()` (or, in netproxy's case, continuing to run
   with whatever partial state resulted). A typo (a stray tab, an unclosed
   bracket) would silently swap the enforced policy for the permissive
   built-in baseline with no indication to the operator, and without ever
   refusing to launch.

Separately, `mcp.allowed` / `mcp.blocked` glob patterns were never validated
at load time the way `disabled_rules` patterns already are -- a malformed
MCP glob would only surface as a Rego evaluation quirk at runtime, not a
load-time error.

## Decision

### MCP-derived hosts: a third, conditional tier

Add `agentpolicy/config/mcphosts.go` with a typed `HostedMCP` registry:

```go
type HostedMCP struct {
    Name           string
    ServerPatterns []string // aliases as they appear in mcp.allowed/mcp.blocked
    Hosts          []string // vetted hosts this MCP's traffic flows through
}

func HostedMCPRegistry() []HostedMCP
func HostedMCPAllowedHosts() []string
func MCPDerivedAllowedHosts(mcp MCPConfig) []string
```

`MCPDerivedAllowedHosts` includes a registry entry's `Hosts` iff the entry is
**effectively allowed**: some `ServerPatterns` alias matches an
`mcp.Allowed` glob, AND no alias matches an `mcp.Blocked` glob. This mirrors
`mcp_policy.rego`'s precedence exactly (blocked always wins), using
`path.Match` the same way `validateDisabledRules` already does for
`disabled_rules` -- MCP server names never contain `/`, so `path.Match` is
equivalent to Rego's `glob.match(pattern, [], name)` here. A malformed
pattern is treated defensively as "no match," never a panic (defense in
depth; malformed `mcp.allowed`/`mcp.blocked` patterns are now rejected at
load time -- see below).

`(*PolicyConfig).EffectiveAllowedHosts()` becomes three tiers, essentials
first, order-stable, deduplicated across all three:

1. **Essential** (`EssentialAllowedHosts`) -- always present, non-removable.
2. **MCP-derived** (`MCPDerivedAllowedHosts(c.MCP)`) -- non-removable WHILE
   the corresponding MCP server stays in `mcp.allowed` and is not matched by
   `mcp.blocked`. Removing the server from `mcp.allowed`, or adding a
   pattern to `mcp.blocked` that matches it, removes its hosts from the
   effective allowlist on the very next load -- this tier tracks the MCP
   gate's own decision, it does not grant anything beyond what
   `mcp_policy.rego` already allows.
3. **Editable** (`Network.AllowedHosts`) -- the user's own list, fully
   removable/replaceable, as before.

### Single source of truth

`ExtendedDefaultAllowedHosts()`'s "Hosted MCP servers" section is now built
by calling `HostedMCPAllowedHosts()` instead of listing the same host
literals a second time. The registry entries (linear, typefully, posthog,
context7, notion, deepwiki, cloudflare, githubcopilot, huggingface) are the
same hosts ADR 0038's extended list already carried -- this change removes
the duplication, it does not add new hosts to the extended default. A drift
test (`TestExtendedDefaultHostedMCPSectionMatchesRegistry`) fails the build
if the two representations diverge again.

### mcp-proxy.anthropic.com is essential

Added to `EssentialAllowedHosts()` (exact hostname, no wildcard, matching
the existing essential-tier convention) because claude.ai's hosted
connectors (Gmail, Google Calendar, Google Drive, typefully) proxy through
it and silently break under the shield without it.

### mcp.allowed / mcp.blocked glob validation at load

`validateMCPGlobs` mirrors `validateDisabledRules`: every entry in
`mcp.allowed` and `mcp.blocked` is probed with `path.Match(pattern,
"probe")` at decode time. A malformed pattern makes `Load`/`decode` return
an error instead of reaching OPA evaluation or `MCPDerivedAllowedHosts` with
a pattern that would only fail (or silently no-op) at runtime.

### Fail-loud on a malformed EXISTING policy.yaml

`config.LoadOrDefault` already distinguished "file does not exist" (via
`errors.Is(err, os.ErrNotExist)`) from "file exists but failed to
parse/validate" -- it returned the error in the latter case. The gap was
that the two enforcement-path callers didn't honor that distinction:

- **`agentjail-shield`'s `main.go`** called `config.Load` directly and
  treated every error, including a parse error on a present file, as "use
  `config.Default()`." Changed to check `errors.Is(err, os.ErrNotExist)`
  explicitly: a missing file still falls back to defaults (unchanged,
  first-run behavior); a present-but-malformed file now prints the file
  path and parse error to stderr and calls `os.Exit(1)` -- the shield
  refuses to launch the agent rather than silently downgrading the enforced
  policy.
- **`agentjail-netproxy`'s `proxy.run`** called `reloadPolicy` (log-and-continue
  on error) for both the initial startup load and SIGHUP reloads. Split into
  two methods: `loadInitial` (startup) returns an error that `run` propagates,
  which `main` turns into a fatal `os.Exit(1)` -- there is no prior "last-good"
  state at startup to fall back on, so failing here must stop the proxy from
  ever listening with an empty or fall-open allowlist. `reloadPolicy` (SIGHUP)
  keeps its original behavior unchanged: on error, it logs and keeps the
  last-good allowlist in place -- a broken policy.yaml after a hot reload must
  neither fall open nor crash the already-running proxy.

## Consequences

- **No silent trust of a broken config.** A present-but-invalid
  `policy.yaml` now stops the shield from launching the agent at all, and
  stops the netproxy from starting, instead of quietly enforcing a more
  permissive built-in default. This is intentionally more disruptive than
  before -- a broken policy file is now a hard failure, not a downgrade.
- **A curated `allowed_hosts` can no longer silently orphan an allowed MCP
  server.** Allowing an MCP server in `mcp.allowed` is now sufficient by
  itself to reach that server's vetted hosts, without also having to
  remember to add them to `Network.AllowedHosts`.
- **Blocked still wins.** `MCPDerivedAllowedHosts` mirrors
  `mcp_policy.rego`'s deny-precedence; an `mcp.blocked` pattern that matches
  a hosted MCP's aliases removes its hosts from the effective allowlist even
  if `mcp.allowed` would otherwise match.
- **claude.ai connectors (Gmail/Calendar/Drive/typefully) work under the
  shield** without requiring a manual `allowed_hosts` addition for
  `mcp-proxy.anthropic.com`.
- **No `.rego` changes.** All of this is Go-side config plumbing; the MCP
  gate's own allow/block/deny logic in `mcp_policy.rego` is unchanged --
  `MCPDerivedAllowedHosts` only mirrors its precedence, it does not
  duplicate or replace it.
- **Scope note:** like ADR 0038, this is domain control (which hosts the
  agent can reach), not exfil-proofing -- a hosted MCP server's host being
  reachable does not itself guarantee the MCP call's content is safe; that
  remains `mcp_policy.rego`'s job.
