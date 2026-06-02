# 0012 — Daemon config overlay: project policy.yaml into OPA data

Status: Accepted

## Context

`~/.agentjail/policy.yaml` is the user-facing configuration surface
(`agentpolicy/config`): MCP allow/block lists, file extra-allow/deny, command
extra-block, network allowed-hosts. The Rego policies are written to read this
config from `data.agentjail.config` (e.g. `mcp_policy.rego` reads
`data.agentjail.config.mcp.allowed`, falling back to a safe deny-all default).

But the daemon never wired it. `cmd/agentjail-daemon/main.go` treated `--policy`
as a "future data overlay" and only loaded Rego modules; it never called
`config.Load()` nor injected anything into the OPA engine. Consequently
`data.agentjail.config` was *always absent at runtime*, every config-driven rule
fell back to its safe default, and `mcp_policy.rego`'s `else := []` made the MCP
allowlist permanently empty — **every MCP call was denied regardless of
policy.yaml**. A user who had already installed an MCP server (e.g. claude-mem)
found it silently blocked with no working way to allow it. The same missing
overlay was independently identified as a prerequisite by the command-policy
bypass plan (strict-mode / per-server tool allowlists also need it).

`NewHookOPAEngine` accepted only modules + query, so there was no way to inject
OPA data; `config.Load` returned only the parsed YAML, so a partial policy.yaml
(e.g. one that set only `mcp.allowed`) would have dropped the default `blocked`
patterns; and the decision cache key deliberately omitted `cwd`, which becomes
incorrect once file decisions vary by working directory (see ADR 0013).

## Decision

The daemon now loads `policy.yaml` and injects it into OPA as
`data.agentjail.config`:

- **Engine data injection.** Add `NewHookOPAEngineWithData(ctx, modules, data)`
  which wires an in-memory OPA store (`rego.Store(inmem.NewFromObject(...))`)
  under the `agentjail` root. `NewHookOPAEngine` delegates to it with `nil`
  (back-compat preserved).
- **Merge over defaults.** `config.LoadOrDefault` loads policy.yaml and merges it
  *over* `config.Default()`, so a partial file keeps the default MCP `blocked`
  patterns and other baseline lists. Absent file ⇒ `Default()` (no error).
- **Config → OPA shape.** `(*PolicyConfig).ToOPAData()` projects the nested
  `mcp` / `file` / `commands` / `network` subtree the Rego expects.
- **Temp roots.** The daemon injects resolved temp roots
  (`data.agentjail.config.file.temp_roots` = canonical `os.TempDir()` plus
  `/tmp`, `/private/tmp`) for ADR 0013's temp-allow rule. `FileConfig.TempRoots`
  is `yaml:"-"` — injected programmatically, never read from policy.yaml.
- **Path canonicalization at ingest.** Before evaluation the daemon canonicalizes
  the request's `file_path`/`path`/`old_path` and `cwd` (clean → absolutize
  against cwd → `EvalSymlinks` on the path or nearest existing parent → reattach
  missing suffix), failing closed on unresolvable sensitive-looking paths. This
  makes every policy see real, absolute paths (defeats `..`/symlink escapes) and
  is required for ADR 0013's `in_project` boundary check.
- **Cache key includes cwd.** `hookCacheKey` now hashes the canonical `cwd` and
  path, so a decision that differs by working directory can no longer be
  mis-served from cache.
- **SIGHUP reload + invalidation.** SIGHUP reloads Rego modules *and* policy.yaml,
  re-merges over `Default()`, rebuilds the engine atomically, and invalidates the
  decision cache. On any reload failure the daemon keeps the old config and logs
  clearly — it never goes open and never crashes. `config.Save` (atomic
  temp-file + rename, 0600) is provided for the forthcoming `agentjail mcp`
  CLI / install seeding.

Strict YAML (`KnownFields(true)`) is retained: an unknown top-level key fails
daemon startup loudly rather than silently ignoring misconfiguration.

## Consequences

- `policy.yaml` is now actually enforced. Setting `mcp.allowed` (or any config
  list) takes effect on next start / SIGHUP. This unblocks MCP trust-on-install
  and the `agentjail mcp allow/block` CLI.
- File decisions may legitimately vary by `cwd`; the cache key change is a
  prerequisite, not optional.
- The in-memory store uses the OPA v0 `storage`/`inmem` packages, consistent with
  the existing `opa/rego` v0 usage in `engine.go`; a future v1 migration is a
  separate change.
- Reload is fail-safe by construction: bad YAML or bad Rego leaves the last-good
  policy in force.
