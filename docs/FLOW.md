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
   ┌──────────────────────────────────┐
   │ 3. ensure agentjail-netproxy      │  ONE shared per-host enforcer (localhost:9100).
   │    (fingerprint + reuse OR start) │  Mint a session token, register THIS session's
   │    register this session          │  resolved allowlist over the control socket.
   │    if it fails -> STOP             │  (fail closed; --no-netproxy is the opt-out)
   └──────────────────────────────────┘
                 │
                 ▼
   ┌──────────────────────────────────────┐
   │ 4. apply OS sandbox + env             │  file denies, env cleaned,
   │    HTTPS_PROXY=<token>:@127.0.0.1:9100 │  agent forced through netproxy;
   │    control socket denied to the agent  │  token selects this session's allowlist
   └──────────────────────────────────────┘
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

## Per-folder overlays (trusted projects)

A repo can carry its own `./.agentjail/policy.yaml` to widen its session's
allowlist (e.g. add an internal DB host). Because that file lives in the repo and
is attacker-controllable, it is **ignored until you trust it** -- direnv-style:

```
$ cd my-backend && claude
  agentjail: ./.agentjail/policy.yaml found but NOT trusted -- ignoring it
             run 'agentjail trust' to apply this project's policy
$ agentjail trust        # shows what it adds, records the file's content hash
$ claude                 # now the overlay applies for sessions started here
```

Rules that keep this safe:

- **Additive-only.** A project overlay may only WIDEN (`network.allowed_hosts`,
  `mcp.allowed`) or ADD blocks (`mcp.blocked`). It can never drop the essentials,
  un-block a blocked MCP, or clear `disabled_rules`.
- **Trust is hash-gated.** Editing the file after trusting it revokes trust until
  you re-approve (`agentjail trust list` shows `CHANGED`). Discovery stops at the
  git root and never treats the global `~/.agentjail` as a project.
- **Tamper-proof.** `~/.agentjail/trusted.yaml` is agent-unwritable (the shield's
  read-only `~/.agentjail` grant), so the agent cannot self-trust a project.

The shield registers the resolved (global + trusted-overlay) allowlist as that
session's policy -- so two trusted repos get different egress through one proxy,
with no bleed. See [ADR 0043](./adr/0043-per-folder-policy-overlay-trust-gate.md).

## How a network request is allowed or blocked

```
agent makes an HTTPS request
        │  (HTTPS_PROXY carries this session's token + OS sandbox blocks direct egress)
        ▼
agentjail-netproxy (localhost:9100)
        │  CONNECT host:port  with Proxy-Authorization: Basic <token>
        │  known token?  ── no ──> refuse (407): missing/unknown session token
        │       │ yes
        │  host in THIS session's allowed_hosts?
        ├─ yes -> tunnel through
        └─ no  -> refuse (403): "host not in this session's network.allowed_hosts"
```

`netproxy` is the enforcer, and it is **session-aware**: one shared proxy holds a
separate allowlist per session, keyed by an unguessable token the shield injects
into `HTTPS_PROXY`. There is no global fallback -- an unknown token is denied. The
OS sandbox's job is narrower: make sure the agent cannot bypass the proxy (no
direct sockets, everything must go to localhost:9100) and cannot reach the
control socket that registers allowlists. A fresh session registers its allowlist
at launch (no `SIGHUP` reload); see
[ADR 0042](./adr/0042-session-aware-netproxy-control-plane.md).

## Safety properties added by ADR 0040 / 0041

| Situation | Behavior |
|-----------|----------|
| Allow an MCP but forget its host | Host is auto-derived; nothing to forget |
| claude.ai connectors under the shield | `mcp-proxy.anthropic.com` is essential |
| A typo (e.g. a stray tab) in `policy.yaml` | Refuses to launch (fail loud), never silently reverts to defaults |
| `netproxy` fails to start | Refuses to launch (fail closed), never silently weakens to port-only egress |
| Wildcard hosts (`*.claude.ai`) | Classified as wildcards, kept netproxy-only, not fed to DNS |
| Another session's proxy is already running | Fingerprinted; reused only if protocol-compatible, else refuse (never silently inherit a stale allowlist, never blind-kill it) |
| Something unverifiable is on `:9100` | Refuses to launch (fail closed); does not route through or kill an unknown listener |
| Agent tries to reach the control socket | Denied: read-only `~/.agentjail` grant (Linux) / sbpl `network-outbound` deny (macOS); the injected token is a data-plane bearer only |
| A cloned repo ships `./.agentjail/policy.yaml` | Ignored until `agentjail trust` (direnv-style); it can only widen, never weaken; editing it revokes trust |
| Agent tries to self-trust a project overlay | Denied: `~/.agentjail/trusted.yaml` is agent-unwritable (enforcement-tested) |

## Related docs

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) -- full architecture (hook, daemon, OPA, tiers)
- [`SANDBOX.md`](./SANDBOX.md) -- `agentjail-shield` user guide and network enforcement detail
- [ADR 0040](./adr/0040-mcp-derived-hosts-and-fail-loud-config.md), [ADR 0041](./adr/0041-hostpattern-cursor-hosts-netproxy-fail-closed.md)
