# agentjail -- how a shielded session flows

A plain-language walkthrough of what happens when you run a coding agent under
`agentjail-shield`, how the network allowlist is decided, and how a request is
actually allowed or blocked. For the deep dive see
[`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`SANDBOX.md`](./SANDBOX.md).

## Launch flow

```
you run:  claude   (wrapped by agentjail-shield)
                 │
                 ▼
   ┌──────────────────────────────┐
   │ 1. agentjail-shield starts   │
   └──────────────────────────────┘
                 │
   load policy.yaml -> LoadPolicyForEnforcement
                 │     - no file       -> built-in defaults
                 │     - file OK        -> your config merged over defaults
                 │     - file malformed -> STOP, refuse to launch (fail loud)
                 ▼
   ┌──────────────────────────────┐
   │ 2. compute allowed hosts     │   EffectiveAllowedHosts()
   └──────────────────────────────┘
                 │
                 ▼
   ┌──────────────────────────────┐
   │ 3. start agentjail-netproxy  │   the real per-host enforcer (localhost:9100)
   │    if it fails -> STOP        │   (fail closed; --no-netproxy is the opt-out)
   └──────────────────────────────┘
                 │
                 ▼
   ┌──────────────────────────────┐
   │ 4. apply OS sandbox + env    │   file denies, env cleaned,
   │    HTTPS_PROXY=127.0.0.1:9100 │   agent forced through netproxy
   └──────────────────────────────┘
                 │
                 ▼
         your agent runs, sandboxed
```

## The allowed-hosts model -- three tiers

```
Effective allowed hosts  =  ESSENTIAL  ++  MCP-DERIVED  ++  YOUR LIST
                            (locked)       (automatic)      (editable)
```

1. **Essential** (`EssentialAllowedHosts`) -- Anthropic / OpenAI / Google auth
   plus `mcp-proxy.anthropic.com`. Always present, non-removable. This is why
   agent login and the claude.ai connectors always work under the shield.
2. **MCP-derived** (`MCPDerivedAllowedHosts`) -- for every MCP server your policy
   allows (`mcp.allowed` and not `mcp.blocked`), its network host is added
   automatically from the built-in `HostedMCPRegistry`. Allow `linear-server`
   and `mcp.linear.app` comes along for free. Uses the same allowed-vs-blocked
   precedence as `mcp_policy.rego` (blocked wins). See
   [ADR 0040](./adr/0040-mcp-derived-hosts-and-fail-loud-config.md).
3. **Your list** (`network.allowed_hosts` in `policy.yaml`) -- fully editable
   (dev registries, internal services, etc.).

The three are concatenated, deduplicated, essentials first. `netproxy`, the
shield, and the OPA policy data all read this single computed list.

**Rule of thumb:** allow an MCP in `mcp.allowed` and its host is handled for you.
You should not need to hand-edit `network.allowed_hosts` for MCP servers.

## How a network request is allowed or blocked

```
agent makes an HTTPS request
        │  (HTTPS_PROXY set + OS sandbox blocks direct egress)
        ▼
agentjail-netproxy (localhost:9100)
        │  CONNECT host:port  ->  host in effective allowed_hosts?
        ├─ yes -> tunnel through
        └─ no  -> refuse: "host not in network.allowed_hosts"
```

`netproxy` is the enforcer. The OS sandbox's job is narrower: make sure the agent
cannot bypass the proxy (no direct sockets, everything must go to localhost:9100).
Config changes reload live via `SIGHUP` to netproxy; a fresh session picks them
up on launch.

## Safety properties added by ADR 0040 / 0041

| Situation | Behavior |
|-----------|----------|
| Allow an MCP but forget its host | Host is auto-derived; nothing to forget |
| claude.ai connectors under the shield | `mcp-proxy.anthropic.com` is essential |
| A typo (e.g. a stray tab) in `policy.yaml` | Refuses to launch (fail loud), never silently reverts to defaults |
| `netproxy` fails to start | Refuses to launch (fail closed), never silently weakens to port-only egress |
| Wildcard hosts (`*.claude.ai`) | Classified as wildcards, kept netproxy-only, not fed to DNS |

## Related docs

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) -- full architecture (hook, daemon, OPA, tiers)
- [`SANDBOX.md`](./SANDBOX.md) -- `agentjail-shield` user guide and network enforcement detail
- [ADR 0040](./adr/0040-mcp-derived-hosts-and-fail-loud-config.md), [ADR 0041](./adr/0041-hostpattern-cursor-hosts-netproxy-fail-closed.md)
