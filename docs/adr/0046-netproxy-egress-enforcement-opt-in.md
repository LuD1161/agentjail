# 0046 - netproxy egress enforcement is opt-in until the transparent tunnel

Status: Accepted (interim; superseded when the transparent tunnel lands)

## Context

`agentjail-shield` wraps a coding agent in an OS-native sandbox (Seatbelt on
macOS, Landlock on Linux) and, when enabled, routes the agent's egress through
`agentjail-netproxy` for per-host `network.allowed_hosts` enforcement. Until
now netproxy was **on by default**; `--no-netproxy` was the explicit opt-out to
port-only filtering (TCP 80/443, no per-host enforcement).

Two problems made the default-on posture a net negative on macOS:

1. **It breaks Claude Code's MCP transport.** ADR 0044 added a per-session token
   to the injected proxy URL (`http://<token>:@127.0.0.1:9100`) so a shared
   `:9100` proxy could key per-session allowlists. Claude Code's main API client
   tunnels through the credentialed proxy URL fine, but its MCP HTTP transport
   (undici/fetch) does not -- it fails to reach the proxy, yielding
   `ConnectionRefused` and a slow `/mcp`. The credential is the trigger; before
   the token it worked.
2. **The macOS sandbox cannot express host-level egress anyway.** Seatbelt's
   `(remote tcp/udp "HOST:PORT")` filter only accepts `*` or `localhost` as the
   host; literal IPs are rejected (see ADR 0037/0039 context). So the sbpl side
   of enforcement is already "localhost-only + proxy" -- when the proxy is the
   thing breaking MCP, the whole feature is friction with little residual value.

The **transparent tunnel** (on Linux via netns/WireGuard, on macOS
via NetworkExtension) will supersede the proxy entirely: it captures egress at
the network layer with no proxy env injected, so there is no credentialed-URL
class of bug, and it provides real per-session isolation (per-peer / per-netns)
rather than a token on a shared port. Given that, keeping the fragile proxy on
by default buys little and costs working MCPs.

The filesystem, process, and keychain sandbox -- the bulk of the shield's
protection -- is independent of netproxy and stays fully on regardless.

## Decision

Make per-host egress enforcement **opt-in**. The shield runs **port-only by
default**; `--netproxy` turns netproxy (and per-host `network.allowed_hosts`
enforcement) back on.

- New flag `--netproxy` (default `false`) enables netproxy.
- `--no-netproxy` is retained for back-compat (now redundant with the default);
  if both are given, disable wins.
- Effective disable is computed by `resolveNoNetproxy(netproxyEnable, noNetproxy)
  = !netproxyEnable || noNetproxy` (unit-tested in `main_test.go`).
- The fail-closed behavior when netproxy **is** requested but cannot start
  (ADR 0041) is unchanged: `--netproxy` + a missing/unstartable binary aborts
  the launch rather than silently downgrading.
- No proxy env is injected and no netproxy is spawned in the default path.
- Runtime host grants (ADR 0044, `agentjail allow`) are token-bound and thus
  dormant while netproxy is off; they return with the proxy under `--netproxy`.

## Consequences

- **MCPs work on macOS by default** -- no credentialed proxy URL, no
  `ConnectionRefused`, fast `/mcp`.
- **Egress host-allowlisting is off by default.** A shielded agent can reach any
  host on 80/443; `network.allowed_hosts` is not enforced unless `--netproxy` is
  passed. This is a conscious, documented interim trade-off, narrowly scoped to
  the network dimension; filesystem/process/keychain sandboxing is unaffected.
- **The token/registration/lease/grant machinery is retained, not removed.** The
  transparent tunnel work (or re-enabling `--netproxy`) restores per-session
  enforcement without re-plumbing.
- **Superseded when the tunnel lands.** This ADR is interim; the tunnel ADR will
  flip the default back to "enforced" (transparently) and mark this Superseded.
