# ADR 0093: an SNI tier — host policy without decryption, and it is not a boundary

**Status:** Proposed

Scope: what the tunnel does when TLS interception is **off**. It does not touch
the default posture ([ADR 0077](./0077-tunnel-mitm-default-and-consent.md)), nor
whether a session is tunneled at all ([ADR 0078](./0078-lazy-tunnel-consent.md)).

## Context

[ADR 0077](./0077-tunnel-mitm-default-and-consent.md) made interception the
tunnel's default on one piece of evidence: without it, the DSL does not reach
HTTP(S) at all. Its own table:

| Traffic | Interception off | Interception on |
|---|---|---|
| postgres / redis / mongo / ssh | enforced | enforced |
| HTTP / HTTPS | **not enforced** — HTTP 200 | denied — HTTP 403 |

It called the cause structural: `netpolicy.RecognizeTCP` dispatches only on
5432/6379/27017/22, every other port falls back to a generic `connect`
operation, and HTTP recognition is reachable only through the MITM handler. So a
user who writes a `host:` deny rule, loads the pack, and runs `--no-mitm` gets a
**silent policy no-op** — the failure agentjail exists to prevent. Faced with
that, 0077 chose "decrypt unless you say no" over "silently ignore your policy
unless you say yes", and it was right to.

But it conflated two capabilities. "Reach HTTP(S)" is `path:`, bodies, and the
service recognizers. **A `host:` rule is not one of those, and never needed a
decrypted stream.** The ClientHello's SNI is cleartext. Nothing about denying a
host requires holding a key the agent trusts.

Three findings from the implementation investigation (AGE-217) shape what
follows.

**The tunnel already knows the hostname.** `Gateway.handleConn` resolves the
destination through `registry.Lookup(dstIP)` — our own resolver minted that VIP
for that name, before any TLS byte arrived. So this ADR is *not* about learning
the destination. It is about wiring a host we already know into the DSL, about
the one case where we do not know it (an agent that skips DNS and dials an IP
literal), and about what it means when the two host claims disagree.

**The mechanism is already in the file.** `handleConn` peeks the first bytes,
recognizes a protocol from them, replays them upstream, and splices both
directions with half-close propagation. That is the entire architecture of an
SNI tier. What is missing is a ClientHello parser and a `443` case.

**Two bugs make `host:` mean two things.** The fallback builds
`Host: "example.com:443"`; the MITM path builds `Host: "example.com"`
(AGE-220). `matchGlobList` compares them literally, so the same template matches
under `--mitm` and misses under `--no-mitm` — measured. And the normalizer that
fixes this, `mitm.ParseHostTarget`, lives in a package `netpolicy` cannot
import. Two copies of "what host means" is the drift
[ADR 0034](./0034-platform-backend-shared-contract.md) names, on a different
axis.

## Decision

**When interception is off, the tunnel reads the ClientHello's SNI, enforces
host-level policy on it without terminating TLS, and reports exactly which of
your templates it cannot apply. This is a visibility and hygiene tier. It is not
a containment control.**

### D1 — `host:` means one thing on every path

`Operation.Host` is always the bare, normalized host. The port becomes
`Operation.Port` with a matching `MatchSpec.Port`, rather than being smuggled
into the host string. `ParseHostTarget` moves into `internal/netpolicy` and both
paths call it — one normalizer, no second copy to drift.

This is a bug fix and it stands alone. It ships whether or not the rest of this
ADR does.

### D2 — The SNI is parsed from the bytes we already peeked

A new `netpolicy.ParseClientHello` walks the record, the handshake header, and
the extensions. It lives beside `recognize_postgres.go` and `recognize_ssh.go`
because it is the same thing they are: adversarial bytes in, typed `Operation`
out. No new dependency; Go exports no ClientHello parser.

The alternative — `tls.Server` with a `GetConfigForClient` that captures the
hello and aborts — is rejected. Reading `hello.SupportedProtos` inside a
handshake we intend to complete (`internal/mitm/alpn.go`) is not the same as
using a TLS server as a parser: it needs a conn wrapper to record the bytes for
replay, a second to swallow the alert Go writes on the error path, and a
sentinel error round-tripped through `Handshake()`. Three wrappers to obtain a
string we can parse directly.

The peek must read a **complete** record, not whatever one `Read` returned — a
hello can exceed the current 1024-byte peek and can span segments. Bounded by
one max-size record and a read deadline; everything read is replayed upstream
whether or not it parsed, because the splice must be byte-exact regardless of
our comprehension. The splice itself is unchanged.

A consequence worth having: the tier never touches ALPN, so **h2 survives**.
Under interception it does not (AGE-222).

### D3 — Two host claims, different provenance; the stronger action wins

The VIP host is **attested** — the agent had to ask our resolver for it. The SNI
is **asserted** — the client chose what to write. `Host` is the attested host
when a mapping exists, the SNI when it does not, the IP literal when neither.

When both exist and **disagree, both are evaluated and the stronger action wins**
(deny > ask > allow). An SNI that lies to dodge a deny still gets denied on the
DNS host; an SNI that lies to acquire an allow still gets denied on the DNS host.
The disagreement is audited (`tunnel.sni_mismatch`): inside a tunnel whose DNS we
own, there is no benign reason for it.

There is no `sni:` match key. Authors reason about the host, not about which of
two strings a connection happened to carry. `Operation.SNI` is recorded and
reported; it is not DSL surface.

### D4 — A deny is a fatal `access_denied` alert, and the wire is not the explanation

There is no TLS session to write a 403 into; creating one is the thing this tier
exists not to do. Closing the socket — today's deny — is indistinguishable from a
network fault. So: a 7-byte fatal `access_denied` (49) record on the plain TCP
conn, before dialing upstream. Every TLS stack surfaces it as a refusal rather
than a socket error (`tls: access denied`, not `EOF`).

**It carries a code, not a sentence.** It cannot name the template, and it reads
as *the upstream* refusing — a user will blame the host, not us. Against MITM's
JSON 403 with `X-Agentjail-Deny`, that is a real diagnostic regression. The
explanation therefore lives where the user actually reads it: a `Warn` with
template and reason, a `tunnel.sni_denied` audit event, and a row in
`network_connections`.

**`ask` has no wire form here at all** — no request to hold, no response to
synthesize. It degrades to allow, loudly, and D6 must list it as degraded.

### D5 — A new table, because a connection is not a request

`network_requests` is `(method, path, url) NOT NULL` plus headers, status, and —
per [ADR 0092](./0092-persist-request-bodies.md) D1 — body paths. An SNI-tier
connection has none of those and never can. Reusing the table means sentinels
(`method = "CONNECT"`, `url = "tls://…"`) that lie in exactly the way these ADRs
keep refusing to lie, and `HostStats` would count connections as requests.

So: `network_connections`, same DB, recording ts, the effective host, **both**
`host_dns` and `host_sni` separately (collapsing them destroys D3's evidence),
dst IP/port, whether SNI was present, offered ALPN, the verdict, byte counts, and
elapsed. Nothing outside `internal/mitm` reads `network.db` today, so the table
is free now and expensive later.

ADR 0092's D1 does not apply (no bodies exist). D3 already covers it (the shield
denies the file, not the table). D4 is moot (no headers). **D2's retention must
sweep it**, or it becomes the unbounded one. **D5's "we record" disclosure now
binds the OFF posture too** — which today does not even open the store.

### D6 — The tier must say what it cannot do, every launch

A template using `path:`, `method:`, `scan:`, or a resource selector can never
match without interception. `netpolicy.InertUnderSNI` computes that set at load
and the OFF-posture launch notice names it:

```
tunnel TLS interception OFF (SNI tier) — host rules enforced from the ClientHello
  4 of 11 templates in this pack cannot match without interception:
  [llm-prompt-scan k8s-delete-pods github-force-push slack-dm-exfil]
```

ADR 0077 D4 made the decrypting posture non-silent. This makes the other one
non-silent. It is the most valuable line in this ADR and would be worth shipping
alone.

### D7 — No new flag, no new default

The SNI tier is not selected; it is what "off" now means. ADR 0077's resolution
order is untouched (`--no-mitm` → `--mitm` → `network.tunnel_mitm` → on), the
default is untouched, and D4/D6's announce-the-achieved-posture contract is
untouched. Only the capability of the OFF posture changes. A third flag would
add a posture to explain and a default to argue for a capability nobody wants
("relay opaquely *and* ignore my host rules").

**ADR 0077 D5 gains a case:** a `network.db` failure must **not** disable the
tier. Policy does not depend on the store. We lose the record, say so, and keep
enforcing. Recording and enforcing become independently failable, which they
should always have been.

## Consequences

### What this buys

- **ADR 0077's HTTPS row splits.** `host:` moves from *not enforced* to
  *enforced* under `--no-mitm`; `path:`/body/service still require interception.
  The gap 0077 apologised for narrows without its default moving.
- **Cert-pinned clients, and installs where decryption is forbidden, get
  something real** — no CA, no trusted key, no injected store, no forgery.
- **h2 survives**, unlike under interception.
- **A lie detector** (D3) that nothing else in the product produces.

### What this does not buy — and must never be sold as

- **SNI is client-asserted, unauthenticated, and bound to nothing.** It is not
  tied to the certificate the server presents or to the `Host:` inside the
  stream. A client may send anything, or nothing.
- **A hostile in-namespace process bypasses host-deny trivially:** dial the IP,
  omit SNI. No VIP mapping, no SNI, `Host` is an IP literal, :443 is not a
  managed port, and allow-by-default relays it. **This tier is not a containment
  boundary.** The boundary is the netns egress path. Any doc implying otherwise
  is wrong.
  - The residual is real and deliberately left open: "no VIP mapping AND no SNI
    on :443" stays an allow. Denying it breaks every legitimate IP-literal TLS
    dial — an availability decision that deserves its own ticket and its own
    measurement. This ADR only makes the case **loud** (`tunnel.sni_absent`), so
    that decision is made on data.
- **Domain fronting is invisible by construction.** Allowed SNI outside, denied
  `Host:` inside. Seeing that is reading the headers, which is interception.
  Physics, not backlog.
- **ECH ends this tier silently.** With Encrypted Client Hello the real name is
  encrypted behind a shared public one. Any Cloudflare-fronted upstream can
  enable it unilaterally, host rules stop matching, and nothing about the failure
  looks like a failure. The only mitigation is that no-SNI is loud, never quiet.
  **Prevalence for the upstreams that matter is unmeasured — this ADR should not
  be Accepted until it is.**
- **The deny is a worse diagnostic than the 403** (D4), permanently.
- **`ask` does not work here** (D4).

### Costs accepted

- **A second table in `network.db`**, with the union-view burden landing on the
  first CLI/UI reader that ships.
- **A hand-rolled TLS parser** on adversarial input — mitigated by the existing
  S-F2 panic isolation, exhaustive truncation tests, and a fuzz target, but it is
  a parser we now own.
- **`ParseHostTarget` moves packages** while ADR 0092 D1 is in flight in the same
  package. An alias keeps the rebase cheap; the sequencing still has to be
  coordinated.
- **"agentjail enforces host policy without decrypting" is a marketing sentence
  waiting to be over-claimed.** It is true for a cooperative agent and false for
  a hostile one, and that distinction will not survive being quoted. D6's notice
  and this section are the only defence.

## Related

- [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md) — the posture question
- [ADR 0077](./0077-tunnel-mitm-default-and-consent.md) — interception default; its
  "SNI tier is unbuilt" consequence and capability table are corrected by this ADR
- [ADR 0078](./0078-lazy-tunnel-consent.md) — tunnel consent (untouched)
- [ADR 0079](./0079-agent-netns-veth-vs-userns-tunfd.md) — the userns tunnel; the actual boundary
- [ADR 0034](./0034-platform-backend-shared-contract.md) — one contract, no second copy of "host"
- [ADR 0035](./0035-domain-driven-interface-first-typesafe.md) — the parser belongs in netpolicy
- [ADR 0092](./0092-persist-request-bodies.md) — D1 inapplicable, D2 extended, D3 already covers, D5 now binds the OFF posture
- AGE-217 (this), AGE-220 (host normalization), AGE-222 (ALPN downgrade), AGE-173 (consent UX)
- Plan: [`plans/012-age217-sni-tier.md`](../../plans/012-age217-sni-tier.md)
