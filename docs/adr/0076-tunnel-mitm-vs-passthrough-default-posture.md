# ADR 0076: TLS-terminating MITM vs. transparent passthrough as the tunnel's default posture

**Status:** Accepted

## Context

The transparent tunnel ([ADR 0075](./0075-agent-netns-veth-vs-userns-tunfd.md),
AGE-148) routes an agent's traffic through a userspace forwarder
(`internal/tunnel/`) running in the shield process, fed by an in-namespace TUN
fd. Once packets reach that forwarder, it can operate in one of **two postures**,
and the choice is a genuine trust decision — not an implementation detail.

### Posture A — Transparent passthrough (AGE-148)

The forwarder relays the agent's TLS byte-for-byte to the real upstream. It
never holds a key that the agent trusts, so it never decrypts. Visibility is
limited to what is legible on the wire:

- the destination IP,
- the TLS `ClientHello` **SNI** / cleartext hostname,
- byte counts and timing.

It **cannot** distinguish two endpoints on the *same* host, and it **cannot** see
request or response bodies. On a shared host like Grok's
`cli-chat-proxy.grok.com`, passthrough sees one hostname — it cannot tell
`/v1/responses` (a legitimate chat call) from `/v1/traces` (telemetry
exfiltration), because both ride the same encrypted connection to the same SNI.
Every host-level allow/deny is all-or-nothing.

### Posture B — TLS-terminating MITM (AGE-149)

The shield generates an ephemeral CA in memory (`mitm.GenerateCAInMemory`),
injects **only its public certificate** into the agent's *namespace* trust store
(`ns.InjectCA`, `cmd/agentjail-shield/tunnel_ca_linux.go`), and routes `:443`
through `internal/mitm/`. It terminates the agent's TLS, re-originates a fresh
verified TLS session upstream, and in between gets full L7 visibility:

- per-request method / path / headers,
- the request body (buffered up to 1 MiB for policy evaluation),
- Nuclei-style template policy (`internal/netpolicy`) that can return `403` on a
  denied operation,
- a durable record of every request in `network.db` (`mitm.RequestStore`).

This is the posture that unlocks the product's core value: same-host endpoint
splitting (`/v1/responses` vs `/v1/traces`) and body-level canaries (catching a
secret in a request body).

### Today's behavior

`startTunnel` (`cmd/agentjail-shield/tunnel_shield_linux.go`) treats MITM as
**silently always-on, best-effort**: it calls `setupTunnelCA` + `gw.SetMITM`
unconditionally, and only when CA setup or `network.db` open *fails* does it fall
back to the plain relay (`SetMITM` never called → passthrough). So the strongest
posture — agentjail decrypting the agent's traffic and installing a CA the agent
trusts — is the *default*, chosen for the user without their knowledge, with
passthrough as the fail-open fallback.

### The tension

- **All the high-value control requires MITM.** Per-endpoint policy on a shared
  host and any body inspection are physically impossible under passthrough. If we
  ship passthrough-by-default, the tunnel degrades to little more than the
  hostname-granularity the existing netproxy already gives.
- **But MITM is a real trust decision.** Terminating TLS means agentjail
  decrypts the agent's traffic and installs a CA it controls into the agent's
  trust store. Users should make that choice **consciously**, not inherit it
  silently. A tool that quietly starts decrypting all HTTPS is indistinguishable,
  in mechanism, from the thing agentjail exists to catch.

## Decision (recommended)

**MITM is the default posture, because it is the only way the tunnel delivers its
core value — but it must be loud, tightly scoped, and overridable.** This is
recommended for the maintainer to accept.

Four conditions make MITM-by-default acceptable:

1. **Surfaced loudly.** Enabling interception must emit an unmissable startup log
   naming plainly that TLS is being intercepted for the agent's session (today
   `startTunnel` logs `"tunnel TLS interception enabled"` at `Info` — this should
   be treated as a required, prominent, user-facing notice, not a debug line, and
   accompanied by an `audit_log` event per AGENTS.md's state-change rule).
2. **Scoped to the agent's own namespace trust store only — never the host.** The
   CA is injected via `ns.InjectCA` into the mount-namespace trust store of the
   sandboxed agent ([ADR 0075](./0075-agent-netns-veth-vs-userns-tunfd.md)). It
   MUST NOT touch the host system trust store, the user's browsers, or any
   process outside the shielded session. The blast radius of the injected CA is
   exactly one agent session.
3. **CA private key in memory only — never on disk.** Already enforced (S-C1):
   `GenerateCAInMemory` keeps the key in the shield's memory and persists only
   the public `root.crt`. Because the agent runs as the same host uid with the
   host `/tmp` visible, a persisted `0600` key would be readable by the agent and
   turn the MITM into a self-signed bypass. The key dies with the process.
4. **Overridable to transparent-only.** Users who will not accept decryption must
   be able to force passthrough via a flag/config, keeping the tunnel's IP/SNI
   visibility and netns isolation while forgoing L7 control. This makes the trust
   decision explicit in *both* directions.

As a further privacy mitigation, **request/response bodies are NOT persisted**
(S-C2): `network.db` stores metadata, and credential headers are redacted at the
store boundary ([ADR 0032](../adr/), `mitm/store.go`). Bodies are buffered
in-memory for policy evaluation and then dropped. So even under MITM, the durable
record is metadata plus a policy verdict, not a transcript of the agent's
traffic.

The current silent-always-on behavior is therefore **incomplete, not wrong**: the
mechanism is right; what is missing is the loud surfacing (condition 1) and the
explicit transparent-only override (condition 4). Landing those two is what this
ADR asks for.

## Consequences

**Trust model.** Choosing MITM-by-default means agentjail's honest posture is:
"to give you per-endpoint and body-level control, we decrypt the shielded agent's
HTTPS using a CA we generate and trust, scoped to that agent alone." That is
defensible precisely because of conditions 2 and 3 — the CA never leaves the
session and its key never touches disk — and because of the body non-persistence
mitigation. The claim we must never make is that the tunnel is "just observing"
while MITM is active; the loud startup notice exists to prevent exactly that
misrepresentation.

**CA lifecycle.** The CA is minted per session in memory, injected as a public
cert into the netns trust store, and both are torn down on cleanup
(`caCleanup` removes the temp cert dir; the key was never written). No CA
material outlives the shielded process, so there is no long-lived trust anchor to
rotate, leak, or revoke.

**What breaks in transparent-only mode.** The override is a real capability
downgrade, and users choosing it must understand the loss:

- **No same-host endpoint split.** `cli-chat-proxy.grok.com/v1/responses` and
  `.../v1/traces` are indistinguishable; policy can only allow or deny the whole
  host.
- **No body canary.** A secret placed in a request body passes through opaque;
  only host/SNI/size/timing are visible.
- Policy degrades to hostname granularity — comparable to netproxy, with the
  tunnel's netns isolation retained but its L7 advantage forfeited.

**macOS parity.** The MITM half of the tunnel is Linux-first. The macOS side of
AGE-149 (Network Extension trust injection + termination) remains open; until it
lands, macOS runs the passthrough posture (or netproxy) regardless of the default
chosen here. Per [ADR 0034](./0034-platform-backend-shared-contract.md), the
posture choice, the loud-notice contract, and the transparent-only override are
the shared contract; each OS backend translates trust-store injection into its
own primitive (namespace trust store on Linux, Network Extension on macOS) rather
than re-deciding the posture.

**Fail-open remains the floor.** Independent of posture, any tunnel failure still
falls back — MITM failure → passthrough, tunnel failure → netproxy — so a broken
interception path never chokes the agent's network (the hard constraint from
AGE-148 / ADR 0075).

## Related

- AGE-148 (transparent passthrough tunnel), AGE-149 (TLS-terminating MITM;
  macOS half still open), AGE-165, AGE-170 (this decision).
- [ADR 0075](./0075-agent-netns-veth-vs-userns-tunfd.md) — the unprivileged
  userns + TUN-fd tunnel this posture rides on.
- [ADR 0034](./0034-platform-backend-shared-contract.md) — per-OS backends share
  a canonical contract; the posture, notice, and override belong to that
  contract.
- [ADR 0032](../adr/) — never log credential values; fingerprints/redaction only
  (S-C2 body/header mitigation).
- [ADR 0001](./0001-os-sandbox-enforcement-layer.md) — enforcement-below-the-agent
  philosophy the MITM policy path extends to the network.
- `docs/reviews/2026-07-08-network-visibility-review.md` — S-C1 (CA key never on
  disk) and S-C2 (header redaction) fixes this ADR relies on.
