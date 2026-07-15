# ADR 0077: TLS interception is opt-in, and separate from the tunnel

**Status:** Accepted — supersedes [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md)

## Context

[ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md) decided that
TLS-terminating MITM should be the tunnel's **default** posture, on the grounds
that passthrough degrades the tunnel to the hostname granularity netproxy
already provides. It listed a transparent-only *override* as one of four
conditions.

That reasoning holds for what MITM *buys*. It undervalues what MITM *costs*:

- **It is a trust decision, not a capability toggle.** "agentjail decrypts your
  agent's HTTPS" is the single most surprising thing this product can do. A tool
  that quietly starts decrypting TLS is, in mechanism, indistinguishable from
  the thing agentjail exists to catch. Inheriting that silently is the wrong
  default even when the blast radius is one namespace.
- **It breaks working setups.** Cert-pinned endpoints fail under interception.
  A default that can break an agent on first run is a bad first run.
- **Consent must be asked, not assumed.** An override the user must discover in
  order to *decline* decryption is consent by default. Opt-in inverts that: the
  user asks for decryption, so the trust decision is made knowingly.

The counter-argument — that visibility-only makes the tunnel redundant with
netproxy — overstates the overlap. Even without decryption the tunnel gives
per-session netns isolation, transparent capture of *all* protocols (not just
HTTP CONNECT), and DNS-VIP attribution for non-SNI protocols. That is a real
product on its own.

## Decision

**TLS interception is off by default and must be asked for. The tunnel and the
interception are separate switches.**

### D1 — Separate switches

`--tunnel` routes traffic. `--mitm` decrypts it. `--tunnel` never implies
`--mitm`. Routing an agent's traffic through a policy chokepoint and decrypting
that traffic are different consent decisions and get different flags.

### D2 — Off is the default, and off wins

Interception is on only when explicitly requested: `--mitm` at launch, or
`network.tunnel_mitm: true` in `policy.yaml` for an install with standing
consent. `--no-mitm` overrides both. When the resolution is ambiguous, off wins.

### D3 — Standing consent is a config, not a flag habit

Users who want interception every run set `network.tunnel_mitm: true` once
rather than retyping `--mitm`. This is the "turn it on by default later" path:
consent is still given once, explicitly, and is inspectable in policy.yaml
rather than buried in a shell alias.

### D4 — Both postures are announced

Every tunnel launch states its posture — interception on or off — on stderr and
in the logs. "Tunnel active" alone is ambiguous about the thing users care
about. The claim we must never make is that the tunnel is "just observing"
while MITM is active.

### D5 — Asked-for-but-unavailable is loud

If `--mitm` was requested and interception cannot be set up (CA failure,
`network.db` failure), the tunnel still falls back to the plain relay — fail-open
is the floor (ADR 0075) — but says so plainly. The user asked for decryption and
is not getting it; that must never be silent.

### Retained from ADR 0076

Conditions 2 and 3 of ADR 0076 survive unchanged and are not reopened here: the
CA is injected **only** into the agent's namespace trust store, never the host's;
and the CA private key lives **in memory only**, never on disk. Request/response
bodies remain non-persisted. Those made MITM defensible *when active*; this ADR
only changes *when it becomes active*.

## Consequences

- **Default posture is weaker.** Out of the box the tunnel sees destination IP,
  SNI, and byte counts — no same-host endpoint split
  (`/v1/responses` vs `/v1/traces`), no request-body canary. Users who want the
  product's headline L7 control must ask for it. That is the intended trade: the
  strong posture is one flag away and clearly labeled, rather than silently on.
- **Docs and demos must pass `--mitm`.** Anything showing per-endpoint policy or
  body inspection (the BYOG/Grok material, AGE-165) is demonstrating the opt-in
  posture and must say so.
- **The netproxy overlap is real but partial.** Visibility-only tunnel ≠
  netproxy: netns isolation, all-protocol capture, and DNS-VIP attribution
  remain. ADR 0076's "little more than netproxy" framing is rejected as
  overstated.
- **macOS parity is contract-level.** Per [ADR 0034](./0034-platform-backend-shared-contract.md),
  the switch split (D1), the default (D2), and the announcement (D4) are the
  shared contract; each backend translates trust-store injection into its own
  primitive. The macOS half of interception (AGE-149) is still open, so macOS
  runs visibility-only regardless — which this ADR makes the *correct* default
  rather than a gap.

## Related

- Supersedes [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md)
  (MITM-by-default); AGE-170 (the posture question), AGE-173 (this decision).
- [ADR 0075](./0075-agent-netns-veth-vs-userns-tunfd.md) — the userns tunnel this
  posture rides on; fail-open floor.
- [ADR 0046](./0046-netproxy-egress-enforcement-opt-in.md) — the same opt-in
  shape for netproxy egress enforcement; `--mitm`/`--no-mitm` mirrors it.
- AGE-149 (macOS interception, still open), AGE-165 (the BYOG demo that needs
  `--mitm`).
