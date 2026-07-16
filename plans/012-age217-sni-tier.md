# Plan 012 — AGE-217: an SNI-only inspection tier

**Ticket:** [AGE-217](https://linear.app/agentjail/issue/AGE-217) (parent AGE-81; related AGE-173, AGE-220, AGE-230)
**Draft ADR:** [0092-sni-inspection-tier](../docs/adr/0092-sni-inspection-tier.md)
**Status:** plan only — no code written, nothing committed.

> Filed as `012`, not `011`: `plans/011-daemon-unreachable-policy.md` already
> exists on this branch and `plans/009-unified-audit-log.md` is untracked WIP.
> Two plans sharing a number is the failure ADR 0083 exists to prevent, so the
> number was taken from the next free slot instead of the one requested.

---

## 0. What the investigation actually found

Three findings reshaped the plan versus the brief. They are load-bearing; read
them before the phases.

### F1 — The tunnel already knows the hostname. SNI adds almost no *visibility*.

`Gateway.handleConn` (`internal/tunnel/handler.go:65`) resolves the destination
by VIP, not by SNI:

```go
hostname, ok := g.registry.Lookup(dstIP)
if !ok {
    hostname = dstIP.String()
    log.Warn("no VIP mapping for destination", "ip", dstIP.String())
}
```

The agent's DNS query goes through our own resolver (`dnsvip.Resolve`), which
mints a VIP per hostname. So on the tunnel the destination host is known *before
a single TLS byte arrives*, with or without SNI. The same is true on the
netproxy path, where the host comes from the `CONNECT` line.

**So the tier's value is not "learn the host".** It is three other things:

1. **Wire the known host into the DSL** — today `RecognizeTCP` dispatches only
   on 5432/6379/27017/22, so :443 falls through to a generic `connect` op and
   host rules never fire under `--no-mitm`. This is the silent no-op ADR 0077
   named.
2. **Cover the case where there is no VIP mapping** — an agent that skips DNS
   and dials an IP literal. There, SNI is the *only* host signal.
3. **Cross-check.** DNS-attested host vs client-asserted SNI. A disagreement is
   a lie detector for the common case. This is the tier's one genuinely
   security-relevant asset and it is not in the ticket.

The brief's framing ("read the SNI to learn the destination host") is true only
for case 2. Building this as if it were case 1's mechanism would produce a
worse design.

### F2 — The mechanism is already in the file. This is smaller than it looks.

`handleConn` **already** peeks the first bytes and replays them upstream:

```go
peek := make([]byte, peekSize)      // peekSize = 1024
n, err := c.Read(peek)
peek = peek[:n]
op, recognized := g.recognizeTCP(hostname, dstPort, peek)
// ... later ...
upstream.Write(peek)                 // replay
relay(c, upstream, log)              // bidirectional io.Copy + half-close
```

That *is* "peek the ClientHello, then splice both directions". There is no new
splice to build and no new relay. The work is: a ClientHello parser, a `443`
case in `RecognizeTCP`, and making the peek read a *complete* record rather than
"whatever one `Read` returned".

### F3 — `network.db` has no readers yet.

`grep` for `network_requests` / `RequestStore` outside `internal/mitm/` returns
only `tunnel_shield_linux.go` (the writer). No CLI, no UI server, no
`ReadOnlyStore` method. A new table costs nothing to migrate today and will cost
a lot to add later. This decides Q6.

---

## 1. How the SNI is read without terminating

**Mechanism: parse the bytes we already peeked. No TLS server, no key, no CA.**

### Rejected: `tls.Server` + `GetConfigForClient` abort

The prior art the brief cites (`internal/mitm/alpn.go`) reads
`hello.SupportedProtos` inside `GetConfigForClient` — but that runs *inside a
real handshake we intend to complete*. To use it for peek-only you must:

- wrap the conn so the ClientHello bytes are recorded for replay upstream,
- wrap it again so `tls.Server`'s alert-on-error write is discarded (aborting
  from `GetConfigForClient` makes Go send a fatal `internal_error` alert to the
  client — which would corrupt the stream we are about to splice),
- return a sentinel error and pattern-match it back out of `Handshake()`.

That is three wrappers and a dependency on unspecified error-path write
behaviour, to obtain a string. Rejected.

### Chosen: `netpolicy.ParseClientHello` over the peeked bytes

Go exports no ClientHello parser (`crypto/tls`'s is internal;
`golang.org/x/crypto` has none). So: hand-roll it, in `internal/netpolicy`,
where every other protocol parser already lives (`recognize_postgres.go`,
`recognize_mongo.go`, `recognize_ssh.go` — the last one already parses a raw
banner off the wire). No new dependency. ADR 0035's domain shape: bytes in,
typed `Operation` out, same seam as every sibling.

```go
// internal/netpolicy/recognize_tls.go
type ClientHello struct {
    SNI        string   // "" when the extension is absent
    SNIPresent bool     // absent and empty-string are different facts
    ALPN       []string // free: same extension walk
    Version    uint16
}

// ParseClientHello returns the parsed hello, or ok=false if data is not a
// complete TLS ClientHello. Never panics on adversarial input.
func ParseClientHello(data []byte) (ClientHello, bool)
```

Parse steps (all bounds-checked, all `ok=false` on short/garbage input):

1. Record header: `data[0] == 0x16` (handshake), `data[1] == 0x03`, length at
   `data[3:5]`.
2. Handshake header: `data[5] == 0x01` (client_hello), 3-byte length.
3. Skip `client_version`(2), `random`(32), `session_id`(1+n),
   `cipher_suites`(2+n), `compression_methods`(1+n).
4. Walk extensions. Type `0x0000` = `server_name`: server_name_list → entry with
   `name_type == 0` (host_name) → the name. Type `0x0010` = ALPN.
5. Lowercase the name; reject anything with a NUL, a `/`, or that fails a cheap
   hostname shape check — an SNI is attacker-controlled and ends up in a log
   line, a DB row, and a `filepath.Match` call.

**A real constraint the current code does not meet:** a single `c.Read` is not
guaranteed to return the whole ClientHello, and 1024 bytes is not guaranteed to
hold it (a padded Chrome hello is ~517 bytes; one with a session ticket and a
long ALPN list can exceed 1 KiB; a hello may legally span multiple records).
Today that only cost us a missed recognition on a DB port. Under the SNI tier it
would be a missed *policy decision*, which is worse. So:

```go
// internal/tunnel/peek.go
// peekTLSRecord reads until the first TLS record is complete (length is in
// bytes 3:5), or maxHelloPeek bytes, or the deadline. Returns everything read
// so the caller can still replay it upstream on failure.
func peekTLSRecord(c net.Conn, max int, d time.Duration) ([]byte, error)
```

Bounded by `maxHelloPeek = 16640` (max TLS record + header) and a 2s read
deadline, so a client that opens a connection and dribbles one byte cannot pin a
goroutine. Everything read is replayed regardless of outcome — the splice must
be byte-exact whether we understood the bytes or not.

**Splice: unchanged.** `relay(c, upstream, log)` already does bidirectional
`io.Copy` with `halfCloser` FIN propagation. We add nothing.

**Bonus, worth stating:** the tier never touches ALPN, so h2 survives. Under
MITM it does not (AGE-222 — `NextProtos: []string{"http/1.1"}`, and the
downgrade notice literally advertises `--no-mitm` as the workaround). The SNI
tier is the first posture that is both h2-preserving *and* host-enforcing.

---

## 2. How netpolicy expresses a host-only rule

**No new template shape. `MatchSpec.Host` already exists and already globs**
(`matcher.go:277` → `matchGlobList`). The reason `host:` does not fire today is
not expressiveness — it is two bugs and a missing dispatch.

### 2a. The bug (AGE-217 part 1)

`Gateway.recognizeTCP`'s fallback (`handler.go:~225`):

```go
Host: fmt.Sprintf("%s:%d", hostname, port),   // "example.com:443"
```

vs the MITM path, which sets `Host` to the bare host via `ParseHostTarget`
(AGE-220). `matchGlobList` compares `"example.com"` against `"example.com:443"`
→ no match. Same template, same host, answer depends on a flag. Fix:

- `Operation.Host` is **always** the bare host, on every path.
- **New field `Operation.Port int`**, and **new `MatchSpec.Port []int`** —
  the ticket's "expose port as its own field rather than smuggling it into
  `Host`". `port:` omitted matches every port, so no shipped template changes
  meaning.

### 2b. One normalizer, two paths (ADR 0034's actual point)

`mitm.ParseHostTarget` is the correct normalizer and it is in the wrong package:
`internal/mitm` imports `internal/netpolicy`, so `netpolicy` cannot import it
back. Two copies of "what host means" is precisely the drift ADR 0034 names.

**Move `HostTarget`/`ParseHostTarget` into `internal/netpolicy`**, leave a type
alias + wrapper in `internal/mitm` so the in-flight ADR 0092 D1 work does not
have to rebase across a rename. Both paths then call one function.

### 2c. The dispatch

```go
// internal/netpolicy/recognize.go — RecognizeTCP
case 443:
    return ParseTLSClientHello(host, data)   // nil if not a TLS hello
```

Yielding:

```go
&Operation{
    Protocol: "tls",
    Service:  host,      // the effective host, see 2d
    Verb:     "connect",
    Host:     host,      // bare, normalized
    Port:     443,
    SNI:      hello.SNI, // recorded; NOT what the DSL matches on. See 2d.
}
```

So this template — which a user can write today and which silently does nothing
— starts working:

```yaml
id: deny-pastebin
info: {name: "no pastebins", severity: high, tags: [exfil]}
match:
  protocol: [tls]
  host: ["*.pastebin.com", "pastebin.com"]
action: deny
reason: "TLS to {{.Host}} — host denied without decrypting"
```

### 2d. Which host is `Host` when DNS and SNI disagree (F1, case 3)

Two host claims exist and they have different provenance:

| source | how obtained | trustworthiness |
|---|---|---|
| `registry.Lookup(dstIP)` | our own resolver minted this VIP for this name | attested — the agent had to ask us |
| `hello.SNI` | the client wrote it into the ClientHello | asserted — the client picked it |

Rule, concretely:

- **`Host` = the attested (VIP) host when a mapping exists; the SNI when it does
  not; the IP literal when neither.**
- **When both exist and differ, evaluate twice — once per host — and the
  stronger action wins (deny > ask > allow).** This closes both directions at
  once: an SNI that lies to *dodge* a deny rule still gets denied on the DNS
  host, and an SNI that lies to *acquire* an allow still gets denied on the DNS
  host. Emit `tunnel.sni_mismatch` (audit) on every disagreement; it is a strong
  signal and there is no benign reason for it inside a tunnel whose DNS we own.
- **No `sni:` match key.** Authors should reason about "the host", not about
  which of two strings the connection happened to carry. `Operation.SNI` is
  recorded and reported; it is not DSL surface.

### 2e. Templates that cannot match without interception — say so

This is the highest-value item in the ticket and it is one function.

```go
// internal/netpolicy/tier.go
// InertUnderSNI returns the IDs of templates that can never match without TLS
// interception: any template using path, method, scan, resource_type,
// resource_name, or namespace on an http/tls protocol.
func InertUnderSNI(ts []Template) []string
```

Called from `startTunnel` when interception is off:

```
tunnel TLS interception OFF (SNI tier) — host rules enforced from the ClientHello
  4 of 11 templates in this pack cannot match without interception:
  [llm-prompt-scan k8s-delete-pods github-force-push slack-dm-exfil]
  Run without --no-mitm to apply them.
```

ADR 0077 chose default-on decryption to avoid a silent policy no-op. This
sentence is what makes the *other* posture non-silent. It is worth shipping even
if every other phase slipped.

---

## 3. How a DENY is expressed with no TLS session

There is no session to write a 403 into — writing one would require terminating,
which is the thing the tier exists not to do. Three options:

| option | agent sees | attributable? |
|---|---|---|
| **(a) close the TCP conn** (what `handleConn` does today: `return`) | Go: `EOF` / `connection reset`. curl: `Empty reply from server`. | No — indistinguishable from a network fault |
| **(b) fatal TLS alert `access_denied` (49), then close** | Go: `remote error: tls: access denied`. curl: `error:.. tlsv1 alert access denied`. | Partially — "the server refused me" |
| **(c) terminate and write 403** | a clean 403 | Yes — but this is MITM |

**Chosen: (b).** A 7-byte record on the plain TCP conn *before* dialing
upstream:

```
15 03 03 00 02 02 31
│  │     │     │  └── access_denied (49)
│  │     │     └───── fatal (2)
│  │     └─────────── length 2
│  └───────────────── legacy record version 0x0303
└──────────────────── content type: alert (21)
```

Legal: a server may send a fatal alert in place of a ServerHello, and every TLS
stack surfaces it as a distinct error rather than a socket fault. It costs one
`Write` and no state.

**Be honest about what (b) does not do.** The alert carries a code, not a
sentence. It cannot say "template `deny-pastebin`". Worse, it reads as *the
upstream* refusing — a user will blame `pastebin.com`, not agentjail. So the
wire is not the explanation channel; it never can be at this tier. The
explanation lives in three places the user actually reads:

- a `log.Warn` at deny time with `template` + `reason` (matching the existing
  managed-port deny),
- an audit event `tunnel.sni_denied` (`Entity` = host, `Detail` = template,
  reason, sni, dns_host),
- a `network_connections` row with `policy_action = "deny"` (§6).

Compared to MITM's JSON 403 body with `X-Agentjail-Deny`, this is a real
diagnostic regression and the ADR states it as one.

`ask` has no wire form at all at this tier: there is no request to hold and no
response to synthesize. **`ask` degrades to `allow` + a loud log + an audit
row.** Not silently — the inertness report (§2e) must list `ask` templates as
degraded, same as it lists path-templates as inert.

---

## 4. What selects the tier

**Nothing new. The SNI tier is what the tunnel does when interception is off.**

The ticket scopes this as "make `--no-mitm` less bad", not "add a third
posture". A third flag would mean three postures to explain, three defaults to
argue, and a fresh consent conversation — for zero user-visible gain, since
nobody wants "relay opaquely *and* ignore my host rules".

- **ADR 0077's resolution order is untouched:** `--no-mitm` → `--mitm` →
  `network.tunnel_mitm` → default on. Off still wins ties.
- **The default is untouched.** MITM stays on by default.
- **What changes is only what "off" means:** `--no-mitm` goes from "opaque
  relay, HTTP(S) policy inert" to "opaque relay, host rules enforced, path/body
  rules inert *and reported*".
- **ADR 0077 D4's launch notice changes text, not contract.** The posture is
  still announced every launch, and still the posture *achieved* (D6). The
  "OFF" notice grows the inertness report from §2e.
- **ADR 0077 D5 gains a case.** Today, `network.db` failing to open with MITM
  requested → fall back to opaque relay. Under the SNI tier, `network.db`
  failing must **not** disable the tier: policy does not depend on the store.
  We lose the record, log loudly, and keep enforcing. Recording and enforcing
  become independently failable, which they should always have been.

### The follow-up this unlocks (explicitly NOT in this plan)

`network.tls_passthrough_hosts: ["*.pinned-corp.internal"]` — decrypt
everything except these. That is the actual answer for cert-pinned clients, and
it needs exactly this ClientHello peek to know the host *before* deciding to
terminate.

It is deferred for two reasons. It needs a `prefixConn` (a `net.Conn` that
replays the peeked bytes) threaded into `mitm.Handle`, which currently reads its
own ClientHello via `tls.Server` — a real change to `internal/mitm/mitm.go`,
where **ADR 0092 D1 is in flight**. And it is a separate consent decision (a
per-host decryption carve-out). **File as a follow-up ticket, blocked on
AGE-217 and on 0090 D1 landing.**

---

## 5. What this tier is worth, stated adversarially

### What it does buy

- **Removes a silent policy no-op.** A `host:` deny rule under `--no-mitm` goes
  from "quietly returns 200" to "enforced". Per ADR 0077's own table, that is
  the entire gap it apologised for.
- **Enforcement against a non-adversarial agent.** The realistic threat model
  for Tier 1: a well-behaved agent that has been prompt-injected into fetching
  from `evil.example`. It sends a truthful SNI because its TLS stack does. The
  rule fires. This is most of the actual value and it is fine to say so.
- **A record of asserted intent**, for hosts we never decrypt.
- **No CA, no key the agent trusts, no injected trust store, no cert forgery.**
  Cert-pinned clients work. Compliance objections to decryption evaporate.
- **h2 survives** (AGE-222's downgrade does not apply).
- **A lie detector** — DNS-vs-SNI mismatch (§2d) is a signal nothing else in the
  product produces.

### What it does NOT buy — and must never be sold as

- **SNI is client-asserted, unauthenticated, and unbound to anything.** Nothing
  ties it to the certificate the server presents, or to the `Host:` header
  inside the encrypted stream. A client may send any SNI, or none.
- **A hostile in-namespace process bypasses host-deny trivially.** Dial the IP
  directly, omit SNI. There is then no VIP mapping and no SNI, `Host` is an IP
  literal, and :443 is not a managed port — so the S-D1 fail-closed rule does
  not apply and today's allow-by-default relays it. **The SNI tier is not a
  containment boundary.** The boundary is the netns egress path.
  - *Residual, and it is not small:* "no VIP mapping AND no SNI on :443" is
    presently an allow. Making it a deny is the obvious hardening and it is
    **out of scope here** — it is an availability decision (it breaks every
    legitimate IP-literal TLS dial) that deserves its own ticket and its own
    measurement. This plan makes it **loud** (`Warn` + audit
    `tunnel.sni_absent`) so the decision can be made on data instead of taste.
- **Domain fronting is invisible by construction.** Allowed SNI on the outside,
  denied `Host:` on the inside. Seeing that *is* reading the HTTP headers, which
  *is* MITM. This is physics, not a backlog item.
- **ECH ends the tier silently.** With Encrypted Client Hello the real name is
  encrypted and the outer SNI is a shared public name. Every Cloudflare-fronted
  host can turn this on unilaterally, at which point host rules stop matching and
  nothing about the failure looks like a failure. Mitigated only by treating
  no-SNI/outer-SNI as the loud case, never the quiet one. (Prevalence for the
  upstreams that matter — `api.anthropic.com` et al. — is **not measured**; see
  §8.)
- **It does not narrow the MITM default's justification.** ADR 0077 is about
  `path:`, bodies, and the service recognizers. The SNI tier reaches none of
  them.

**One-line summary for the ADR:** the SNI tier turns a silent no-op into an
enforced host rule for cooperative clients, and into an auditable record for
everyone else. It is a visibility and hygiene tier. It is not a containment
control, and any doc that implies otherwise is wrong.

---

## 6. What `network.db` records

**A new table in the same database. Not `network_requests`.**

Why not the existing table: `network_requests` is `(method, path, url) NOT NULL`
plus request/response headers, status code, and — once ADR 0092 D1 lands —
`request_body_path` / `response_body_path`. An SNI-tier connection has *none* of
those and can never have them. Reusing the table means sentinel values
(`method = "CONNECT"`, `path = ""`, `url = "tls://host"`) that lie in exactly the
way the ADRs keep refusing to lie: `HostStats` would count connections as
requests, and every future reader would need to know which rows are fictional.

`network_requests` is a request/response pair. This is a connection. Different
domain object, different table (ADR 0035).

**F3 makes this nearly free:** nothing outside `internal/mitm/` reads
`network.db` today. No reader to migrate, no union view to maintain. That
changes the moment a CLI/UI lands, so the table is worth adding now.

```sql
CREATE TABLE IF NOT EXISTS network_connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now')),
    host            TEXT NOT NULL,  -- the effective host policy was evaluated on
    host_dns        TEXT,           -- VIP-attested; NULL when no mapping
    host_sni        TEXT,           -- client-asserted; NULL when absent
    sni_present     INTEGER NOT NULL DEFAULT 0,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    alpn            TEXT,           -- offered, comma-joined; free from the parse
    tier            TEXT NOT NULL,  -- "sni" (leaves room for "passthrough")
    policy_action   TEXT,
    policy_template TEXT,
    policy_reason   TEXT,
    bytes_out       INTEGER,
    bytes_in        INTEGER,
    elapsed_ms      INTEGER,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_netconn_ts   ON network_connections(ts);
CREATE INDEX IF NOT EXISTS idx_netconn_host ON network_connections(host);
```

Store surface: `LogConnection(*ConnectionLog) error`, `QueryConnections(...)`,
mirroring `Log`/`Query`. `host_dns` and `host_sni` are kept **separate and both
recorded** — collapsing them into `host` would destroy the mismatch evidence
that §2d exists to produce.

Consequences worth naming:

- **ADR 0092 D1 does not apply.** No bodies exist at this tier; the body columns
  are not on this table. Nothing to store, nothing to cap, nothing to retain.
- **ADR 0092 D3 already covers it.** The shield's deny rule is derived from
  `mitm.DBFileName` + sidecars — one file, both tables. No new shield rule.
- **ADR 0092 D4 (header redaction) is moot.** There are no headers. The only
  attacker-controlled string persisted is the SNI, which §1 shape-checks before
  it reaches a row.
- **ADR 0092 D2 retention must sweep this table too**, or it becomes the
  unbounded one. `bytes_out`/`bytes_in` come from counting wrappers in `relay`,
  which does not count today — a small addition (§7, commit 7).
- **ADR 0092 D5 now binds the `--no-mitm` notice.** "We record" must appear in
  the OFF posture too. Today the OFF path never even opens the store.

---

## 7. Commit-by-commit

Each commit: `go build ./... && go vet ./... && go test ./<pkg>/...` green,
Conventional Commit, `-s` signed. Commits 1–2 are shippable on their own and fix
a live bug; land them first regardless of what happens to the rest.

**Phase A — the bug (AGE-217 part 1). Touches no new concepts.**

1. `fix(netpolicy): the fallback Host is a bare host, and the port is its own field`
   — add `Operation.Port`; `MatchSpec.Port []int`; fix `recognizeTCP`'s
   `fmt.Sprintf("%s:%d")`; add `Port` to `templateData`. Test: a
   `host: [example.com]` template matches the *same* op from both the MITM path
   and the fallback path — the regression the ticket measured.
2. `refactor(netpolicy): one host normalizer for both paths`
   — move `HostTarget`/`ParseHostTarget` from `internal/mitm` → `internal/netpolicy`;
   type alias + wrapper left in `internal/mitm` (keeps ADR 0092 D1's rebase
   cheap). Move `hosttarget_test.go` with it. No behaviour change.

**Phase B — the parser. Pure functions, no wiring.**

3. `feat(netpolicy): parse the TLS ClientHello`
   — `recognize_tls.go`: `ClientHello`, `ParseClientHello`, `ParseTLSClientHello`.
   Table-driven tests: real captured hellos (Go `crypto/tls`, curl/OpenSSL,
   node), no-SNI, TLS 1.3 + GREASE, IP-literal (no SNI by RFC), multi-record,
   truncated at every byte offset, ALPN present/absent, and adversarial input
   (length fields that overflow, NUL in the name, 64 KiB name) → `ok=false`,
   never a panic. Fuzz target for `ParseClientHello`.
4. `feat(tunnel): peek a complete TLS record, not one Read`
   — `peekTLSRecord` with `maxHelloPeek` + read deadline; everything read is
   replayed upstream regardless of parse outcome. Tests: hello split across
   segments; a dribbling client hits the deadline and is relayed, not hung.

**Phase C — wiring. This is where behaviour changes.**

5. `feat(netpolicy): recognize TLS on 443`
   — `case 443` in `RecognizeTCP`. Not a managed port: an unparseable hello
   still relays (S-D1 unchanged).
6. `feat(tunnel): evaluate host policy on the SNI tier`
   — `handleConn`: use `peekTLSRecord` on 443 when `mitmHandler == nil`;
   dual-host evaluation with deny > ask > allow (§2d); `tunnel.sni_mismatch` and
   `tunnel.sni_absent` audit events; `ask` → allow + loud log.
7. `feat(tunnel): deny an SNI-tier connection with a TLS access_denied alert`
   — the 7-byte alert before close; `tunnel.sni_denied` audit event; byte
   counters in `relay` so §6's `bytes_out`/`bytes_in` are real. Test: a Go
   `tls.Dial` against a denied host returns `tls: access denied`, not `EOF`.
8. `feat(mitm): record SNI-tier connections in network_connections`
   — new table + `LogConnection`/`QueryConnections`; retention sweep covers it.
   **Sequence after ADR 0092 D1 lands** — same file, `store.go`.
9. `feat(shieldapp): open the store and wire the tier when interception is off`
   — `startTunnel`'s `!mitmEnabled` branch opens `network.db` and wires the
   connection logger; a store failure logs loudly and **keeps enforcing** (§4).

**Phase D — the honest part.**

10. `feat(netpolicy): report templates that cannot match without interception`
    — `InertUnderSNI`; the OFF-posture launch notice (§2e). New audit event
    `tunnel.templates_inert`.
11. `docs(adr): 0092 SNI inspection tier`
    — the ADR; mark ADR 0077's "SNI tier is unbuilt" consequence resolved and
    correct its capability table; README `--no-mitm` text; `make adr-check`.

New audit constants in `internal/audit/audit.go`: `tunnel.sni_denied`,
`tunnel.sni_mismatch`, `tunnel.sni_absent`, `tunnel.templates_inert`.

**Platform note (ADR 0034):** everything above is in tag-free files. The Linux
userns path and the macOS utun path both funnel through `Gateway.handleConn`
(`gateway_utun_darwin.go:27` documents the same VIP→hostname step), so the tier
reaches both by construction. Nothing per-OS is added. *Read, not run on macOS —
see §8.*

---

## 8. What I could not determine

1. **Whether real ClientHellos fit the current 1024-byte peek.** Not measured.
   Commit 4 makes it moot by construction, but the *size* of the bug it fixes is
   unknown. A capture of Claude Code's (Node) and curl's hellos against
   `api.anthropic.com` would say.
2. **ECH prevalence for the upstreams that matter.** Not measured. If
   `api.anthropic.com` or `github.com` ship ECH, §5's "silent end of the tier" is
   present-tense, not future. This should be checked before the ADR is Accepted.
3. **Go's exact alert-on-error behaviour in `GetConfigForClient`.** Asserted
   from reading, not from running. It only justifies *rejecting* that mechanism,
   so the plan does not depend on it — but the rejection rationale is one rung
   weaker than it reads.
4. **Whether `handleConn`'s deny-by-close is observably different from the alert
   for the clients we care about.** Predicted from the specs; not tested.
   Commit 7's test settles it.
5. **The macOS utun path is read, not run.** `handleConn` is shared, but the
   tunnel's macOS status is unclear from the tree (memory notes an unwired
   `internal/mitm` on both platforms). Whether the SNI tier is *reachable* on
   macOS today is unknown.
6. **Whether moving `ParseHostTarget` (commit 2) collides with in-flight work.**
   `git status` shows `internal/mitm/` clean on this branch, but ADR 0092 D1 is
   in flight elsewhere. Coordinate before commit 2 lands.
7. **Whether the dnsvip registry recycles VIPs**, and what a stale
   `Lookup(dstIP)` would do to §2d's mismatch signal. Not investigated — a
   recycled VIP would produce a *false* mismatch, which would make
   `tunnel.sni_mismatch` noisy and therefore ignored.
8. **Whether `ask` has any tunnel-side plumbing at all.** `handleConn` only ever
   branches on `"deny"`; the grant/ask flow (ADR 0044/0047) was not traced to the
   tunnel. §3's "`ask` degrades to allow" may be describing today's behaviour
   rather than a new degradation.
