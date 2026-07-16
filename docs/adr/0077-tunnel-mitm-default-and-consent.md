# ADR 0077: TLS interception is on by default inside the tunnel, loud, and overridable

**Status:** Accepted — supersedes [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md)

Scope: this ADR governs the posture *inside* a tunneled session. Whether a
session is tunneled at all, and when the user is asked for what that costs, is a
separate decision — see [ADR 0078](./0078-lazy-tunnel-consent.md).

## Context

[ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md) decided MITM
should be the tunnel's default, conditional on four things — loud surfacing,
namespace-scoped CA, in-memory key, and a transparent-only override. It observed
that conditions 1 and 4 were **not implemented**: interception was silently
always-on with no way to decline it.

This ADR was first drafted to reverse that default to opt-in, on the consent
argument: "agentjail decrypts your agent's HTTPS" is a trust decision, an
override you must discover in order to *decline* is consent by default, and
interception breaks cert-pinned endpoints. That argument still stands on its own
terms. It was rejected on evidence.

### The evidence: without interception, the DSL does not reach HTTP(S)

Measured on `feat/network-visibility` with a `host: [example.com]` deny template
loaded:

| Traffic | Interception off | Interception on |
|---|---|---|
| postgres / redis / mongo / ssh | enforced (verb rules match) | enforced |
| HTTP / HTTPS | **not enforced** — HTTP 200 | denied — HTTP 403 |

The cause is structural, not a bug: `netpolicy.RecognizeTCP` dispatches only on
ports 5432, 6379, 27017, and 22. Every other port returns nil and falls back to a
generic `connect` operation. HTTP recognition lives in `netpolicy.RecognizeHTTP`,
which is **only reachable through the MITM handler**. So without interception,
every HTTP(S) template — and every service recognizer (GitHub, k8s, Slack, LLM,
xAI) — is silently inert.

That makes opt-in-by-default the worse failure. A user who writes a deny rule,
loads the pack, and sees no denial has a **silent policy no-op**: the exact
failure mode agentjail exists to prevent, arrived at through a consent-flavored
default. Between "the tool decrypts unless you say no" and "the tool silently
ignores your policy unless you say yes", the second is more dangerous, because
the first is at least announced.

### What the consent argument still wins

It wins conditions 1 and 4 — the ones ADR 0076 admitted were missing. The
mechanism was never the problem; the silence was. It also wins the *tunnel*
axis, where the user's consent is genuinely required before anything costly
happens (ADR 0078).

## Decision

**Interception is on by default inside a tunneled session, because it is the only
way policy reaches HTTP(S) — but it is announced on every launch and overridable
in both directions.**

### D1 — Separate switches, one default

`--tunnel` routes traffic; `--mitm` / `--no-mitm` control decryption. They stay
separate flags because they are separate decisions — but once a session *is*
tunneled, the default includes interception, because a tunnel that cannot apply
the DSL to HTTP(S) is not the product.

### D2 — Default on; `--no-mitm` always wins

Resolution order: `--no-mitm` → `--mitm` → `network.tunnel_mitm` → default on.
Off wins ties. Transparent-only is always reachable in one flag.

### D3 — Standing opt-out is a config, not a flag habit

`network.tunnel_mitm: false` in policy.yaml is a standing transparent-only
posture for installs that will not accept decryption (cert-pinned fleets,
policy-forbidden environments). Absent means on. It is tri-state deliberately:
absent, true, and false are three different statements.

### D4 — Both postures are announced, every launch

Every tunnel launch states whether it is decrypting. This is ADR 0076's
condition 1, now implemented. "Tunnel active" alone is ambiguous about the thing
users care about, and the claim we must never make is that the tunnel is "just
observing" while it decrypts. `agentjail doctor` reports the posture too, so it
is inspectable without launching.

### D5 — Requested-but-unavailable is loud

If interception cannot be set up (CA failure, `network.db` failure), the tunnel
falls back to the plain relay — fail-open is the floor (ADR 0079) — but says so
plainly, because policy silently stops covering HTTP(S) at that moment.

### D6 — CA injection is the last fallible step, and the notice reports what happened

Injecting the CA **replaces** the agent's namespace trust store. An injected CA
with no live MITM therefore leaves the agent trusting only agentjail while it
talks to real upstreams, and every TLS handshake fails — D5's fail-*open* becomes
a fail-*closed* network. So `startTunnel` orders the work: everything fallible
first (open `network.db`), then inject, then `SetMITM` immediately, with nothing
in between that can bail out.

For the same reason the launch notice reports the posture **achieved**, never the
one requested. Interception can be asked for and still fall back; printing
"interception ON" while relaying opaque is the misrepresentation D4 forbids,
pointed the other way.

Both regressed in exactly these ways before being caught, so both are pinned by
tests (`tunnel_ca_order_test.go`).

### Retained from ADR 0076

Conditions 2 and 3 are unchanged and not reopened: the CA is injected **only**
into the agent's namespace trust store, never the host's; the CA private key is
**in memory only**, never on disk. Bodies remain non-persisted — `network.db`
stores metadata plus a verdict, not a transcript.

## Consequences

- **Honest posture.** "To apply policy to your agent's HTTPS, agentjail decrypts
  it with a per-session CA scoped to that agent alone, and says so every launch."
  Defensible because of D4 (announced), conditions 2 and 3 (contained), and D2
  (declinable in one flag) — and because the user chose to tunnel this session at
  all (ADR 0078).
- **Cert-pinned endpoints break by default.** The real cost of this default.
  `--no-mitm` is the escape hatch, and the pinning caveat must be documented
  where users meet the tunnel.
- **Transparent-only is a real capability downgrade, and now an informed one.**
  Choosing it forfeits all HTTP(S) policy — not just body inspection. `doctor`
  warns when `network.tunnel_mitm: false` is set so this is never a surprise.
- **The SNI tier is unbuilt.** Host-level policy is *achievable* without
  decrypting (the ClientHello SNI is cleartext), which would let `host:` rules
  work under `--no-mitm`. Not built here; the generic fallback also sets
  `Host: "host:port"`, so `host:` templates miss on that path today. Worth a
  follow-up — it would make transparent-only meaningfully more than a relay.
- **macOS runs transparent-only regardless.** The macOS half of interception
  (AGE-149) is open, so macOS gets the downgraded posture until it lands — which
  D4 now makes visible rather than silent. Per
  [ADR 0034](./0034-platform-backend-shared-contract.md), the switch split, the
  default, and the announcement are the shared contract.

## Related

- Supersedes [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md);
  AGE-170 (the posture question), AGE-173 (this decision).
- [ADR 0078](./0078-lazy-tunnel-consent.md) — whether a session is tunneled, and
  when the user is asked. This ADR assumes that consent already happened.
- [ADR 0079](./0079-agent-netns-veth-vs-userns-tunfd.md) — the userns tunnel;
  fail-open floor.
- [ADR 0046](./0046-netproxy-egress-enforcement-opt-in.md) — the
  `--flag`/`--no-flag` shape `--mitm`/`--no-mitm` mirrors.
- AGE-149 (macOS interception, open), AGE-165 (BYOG demo — works on the default).
