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
   │ 3. ensure agentjail-netproxy      │  ONLY with --netproxy (opt-in; OFF by
   │    (fingerprint + reuse OR start) │  default in the interim -- ADR 0046).
   │    register this session          │  Mint a session token, register THIS
   │    if it fails -> STOP             │  session's allowlist over the control
   └──────────────────────────────────┘  socket. (fail closed)
                 │
                 ▼
   ┌──────────────────────────────────────┐
   │ 4. apply OS sandbox + env             │  file denies, env cleaned. With
   │    HTTPS_PROXY=<token>:@127.0.0.1:9100 │  --netproxy: agent forced through
   │    control socket denied to the agent  │  netproxy, token selects its allowlist.
   └──────────────────────────────────────┘  Default: port-only egress (80/443).
                 │
                 ▼
         your agent runs, sandboxed
```

> **Interim (ADR 0046):** steps 3-4's proxy path is opt-in (`--netproxy`). By
> default the shield runs port-only (no per-host egress filtering); the
> transparent tunnel (AGE-81/AGE-96) will restore transparent per-host
> enforcement without the proxy env that breaks MCP.

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

## Runtime host grants (mid-session)

Sometimes a session needs one more host right now, and relaunching just to add
it to `policy.yaml` is overkill. `agentjail allow host <h>` lets the agent FILE
a request for its own session; a human approves it from a second, unsandboxed
terminal:

```
$ agentjail allow host db.staging.internal --reason "run migration check"
  requested -- pending approval (grant_id 7f2c...)

# from a normal (unsandboxed) terminal:
$ agentjail grants
  7f2c...  db.staging.internal  ttl=1h  cwd=~/work/backend  "run migration check"
$ agentjail grant approve 7f2c...            # live for this session only
$ agentjail grant approve 7f2c... --persist  # also widen ./.agentjail/policy.yaml
```

The request is filed over `daemon.sock`, the same agent-reachable channel the
hook already uses, so it can only ever request for its own session -- there is
nothing to hand it that would let it request on behalf of another session, and
nothing the request itself grants. Filing a request is inert: the daemon just
remembers "someone asked." The approve/deny/list verbs only run over
`daemon-ctl.sock` (AGE-116), an agent-unreachable control socket protected by
the same mechanism as the legacy `netproxy-ctl.sock`
([ADR 0042](./adr/0042-session-aware-netproxy-control-plane.md)) --
so the agent cannot approve its own request no matter what it does inside the
sandbox.

As of AGE-116 this whole flow -- file, approve, persist -- works in the
default configuration with no `--netproxy` flag: the daemon persists an
approved host into the owning session's trusted overlay automatically, so
future sessions inherit it. Widening the *current, still-running* session's live egress
mid-session still needs `--netproxy`, since that is the component that
actually enforces the per-session allowlist against outbound traffic; without
it, approval affects the next launch, not the live process.
See [ADR 0044](./adr/0044-runtime-host-grants.md).

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
| Agent tries to reach a control socket (`daemon-ctl.sock` or `netproxy-ctl.sock`) | Denied: read-only `~/.agentjail` grant (Linux) / sbpl `network-outbound` deny (macOS); the injected token is a data-plane bearer only |
| A cloned repo ships `./.agentjail/policy.yaml` | Ignored until `agentjail trust` (direnv-style); it can only widen, never weaken; editing it revokes trust |
| Agent tries to self-trust a project overlay | Denied: `~/.agentjail/trusted.yaml` is agent-unwritable (enforcement-tested) |
| Agent files a runtime grant request (`agentjail allow host`) | Inert until approved -- files an in-memory pending entry for its OWN session only, grants nothing by itself |
| A human approves a pending grant from a trusted terminal | Live for that session (TTL-bounded); `--persist` also widens the trusted overlay |
| Agent tries to approve its own grant | Denied: `grant.approve`/`grant.deny`/`grant.list` only run over `daemon-ctl.sock` (AGE-116), agent-unreachable on both OSes |

## Related docs

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) -- full architecture (hook, daemon, OPA, tiers)
- [`SANDBOX.md`](./SANDBOX.md) -- `agentjail-shield` user guide and network enforcement detail
- [ADR 0040](./adr/0040-mcp-derived-hosts-and-fail-loud-config.md), [ADR 0041](./adr/0041-hostpattern-cursor-hosts-netproxy-fail-closed.md), [ADR 0044](./adr/0044-runtime-host-grants.md)
