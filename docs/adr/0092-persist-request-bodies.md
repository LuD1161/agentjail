# ADR 0092: the network store persists full request/response bodies, and the agent may not read it

**Status:** Proposed — supersedes the S-C2 clause of [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md), retained by [ADR 0077](./0077-tunnel-mitm-default-and-consent.md)

> **Amended before implementation (2026-07-15):** D1 originally stored bodies as
> `BLOB` columns inside `network.db`. It does not: bodies are **files on disk**,
> and the DB holds a path. A `BLOB` insert takes one `[]byte`, so "no per-body
> cap" would have meant peak daemon memory equal to the largest body the agent
> chose to fetch — an agent-triggerable OOM of the process meant to police it.
> The original text reasoned carefully about one huge body defeating the *disk*
> budget (D2) and never noticed the same body defeating *memory*, which is why
> the gap read as considered. Recorded inline in D1/D2/D3 rather than as a new
> ADR: at the time nothing on this branch had been built against the original
> text. That was true of *this* branch and false of the repository — see the
> Context, which is the same mistake twice.

## Context

Two things we have written down disagree, and nothing forces the issue *today*
because `network.db` currently has one writer and **zero readers**.

**That is a regression, not a starting point, and this ADR originally got it
wrong.** An earlier draft said "no UI reads `network.db` at all (AGE-111 is
unbuilt)", which framed the consumer as hypothetical. It was built, and it ran:

- `6ceecc3 feat(ui): add Network tab for real-time network request monitoring`
  — a third tab in the web UI over `/api/network/stats` and
  `/api/network/recent`.
- `ff66529 feat(network): MITM TLS inspection proxy with request logging and CLI`
  — the store behind it.
- `190e0dc feat(shield): activate NEPacketTunnelProvider tunnel extension on macOS`
  — which is why it worked **on macOS**, where a user watched real requests and
  responses in the local UI.

All three are **orphaned**: none is an ancestor of `main` or of
`feat/network-visibility`, surviving only on side branches. The "rewritten main"
event stranded them and unwired `internal/mitm` on both platforms (AGE-149).
Today there is no `tunnel_shield_darwin.go` at all, so macOS does not even write
the store, let alone read it.

**And the ADR was wrong a second time, about the bigger claim.** The correction
above still asserted that "the body persistence this ADR decides is the part
that was *never* there — the old tab showed `network_requests` metadata, not
bodies." That is false. Bodies were built too, on the same day, and shipped as a
Burp-style request/response viewer that ran on the author's Mac. It was stranded
by the same history rewrite and survived only in a stale remote-tracking ref;
it is now rescued onto `rescue/burp-ui-2026-07-05`:

- `36ba7ab2 feat(mitm): capture request/response bodies for Burp-style inspection`
  — `RequestBody` / `ResponseBody` / `BodyTruncated` on `RequestLog`, a
  `bodyCapture` tee on the response, columns on `network_requests`.
- `2f3d28ce fix(mitm): decompress gzip response bodies before storing`
- `6ef49e02` / `19ca0c9a` / `0a014948` — the `/network` viewer and its split
  req/resp detail panel.

So **D1 is a restoration, not a greenfield decision**, and the two corrections
compound: this ADR twice re-derived from first principles a thing that already
existed and worked, because the code was invisible to `git log` on this branch.
Both of the ADR's confident "not built" claims came from reading the branch it
was written on and calling that the world. That is the actual lesson, and it is
worth more than either individual fix. The reversal of ADR 0076 S-C2 is not
speculative in either direction: the transcript S-C2 forbade has already been
written to a real database on a real machine.

**The product goal (AGE-79)** is complete visibility:

> a full MITM inspection proxy that gives complete visibility into every network
> call from coding agents — URLs, headers, **request/response bodies** — with
> content-based policy enforcement.

**ADR 0076 (S-C2)** declined exactly that:

> As a further **privacy mitigation**, request/response bodies are **NOT
> persisted**... the durable record is metadata plus a policy verdict, **not a
> transcript of the agent's traffic**.

ADR 0077 retained S-C2 and *leaned on it*: interception is on by default without
asking, and part of why that was defensible is that we decrypt without keeping a
transcript.

So "show the user every request and response for a session" — the thing the
tunnel exists to enable — cannot be built without reversing S-C2. This ADR
reverses it deliberately rather than letting a feature quietly contradict a
decision.

### What is actually in a body

Measured, from a real Claude Code session through the tunnel:

| | |
|---|---|
| a single model turn | a 90–100 KB POST to `/v1/messages` |
| what is in it | the conversation, and **the user's source code** — every file the agent read |
| one short session (build a web app, commit it) | 40 requests, ~1.3 MB of request bodies |
| also present | MCP payloads, npm metadata, vendor telemetry |

If the agent read a `.env`, that `.env` is in a body. This is the point of the
feature and the cost of it, in the same sentence.

### The starting position is not what it looks like

Three facts, verified, that the design has to start from:

1. **The sandboxed agent can read `~/.agentjail/network.db` on Linux.**
   Measured: `network.db` → READABLE; `agentjail.db` → READABLE;
   `~/.config/gh` → denied. The deny mechanism exists
   (`AgentjailReadDeniedNames()`); the databases are simply not in it.
2. **macOS already denies the whole `~/.agentjail` subtree** for reads
   (`sensitiveReadPaths`, `shield_darwin.go`). So this exposure is **Linux-only
   today**, and D3 is Linux catching up to macOS — the reverse of the usual
   asymmetry, where Linux's allowlist is the stricter shape.
3. **Response bodies are not captured on this branch today — because the code
   that captured them was deleted, not because it was never written.** At HEAD,
   `mitm.go` tees the response through a `countingWriter` that counts bytes and
   never buffers it; request bodies are buffered only to `maxBodyScan` (1 MiB),
   beyond which the remainder streams straight through (`io.MultiReader`). That
   is the *regressed* state. The Jul-5 code replaced `countingWriter` with a
   `bodyCapture` that tees into a bounded buffer, stored both bodies, and
   rendered them. So "store bodies" is **restoring a data path, plus fixing two
   bugs in it, plus one deliberate change of tradeoff** — see D1. It is not the
   first attempt at the problem, and the ADR should stop pretending it has no
   prior art to answer to.

## Decision

**Persist full request and response bodies -- whole, unredacted, bounded only by
retention -- and deny the sandboxed agent read access to the store.**

### D1 — Bodies are persisted whole, as files; there is no per-body cap

Bodies are written to **`~/.agentjail/bodies/`, one file per body**, and
`network_requests` gains `request_body_path` / `response_body_path` columns
holding a store-relative path. Every body is stored in full. **No per-body size
limit**: "save everything" means everything, and the measured traffic says a
limit would rarely bite — across 110+ requests of a real Claude Code session the
largest body was 1.3 MB (a web page), and the model turns were 1.7–3.5 KB each.
Only the retention bounds in D2 apply.

**Removing the cap is the change, and it is what creates the memory problem.**
The Jul-5 code capped stored bodies at `maxBodyStore = 256 KiB` and set a
`body_truncated` flag past it. That cap is precisely what bounded memory: the
capture buffer could not exceed 256 KiB per body no matter what the agent
fetched. Nobody ever hit an OOM, because nothing was ever unbounded. So the ADR
must not tell itself the story that it is fixing a flaw in a naive design — it
is not. It is taking a **different tradeoff, deliberately**: "save everything"
is an instruction that trades a bounded buffer for an unbounded one, and the
file sink is the price of honouring it. Truncation was the old design's answer
to the same question, and it was a defensible one; we are rejecting it because a
truncated transcript is not a transcript, not because it was wrong.

**Given no cap, files rather than `BLOB`s, and the reason is memory, not taste.**
A `BLOB` insert takes one `[]byte`: the whole body must be resident at `INSERT`
no matter how carefully the proxy tees on the way in. Uncapped, peak daemon
memory would equal the largest body the agent chose to fetch — so `curl`ing a
multi-GB file would OOM the daemon, and the shield fails open when the daemon
dies. That turns a recording feature into a way to switch off enforcement, which
is not a trade this ADR will make. A file sink is bounded by the copy buffer
instead, and it is what makes "no per-body cap" honest rather than aspirational.
Note the dependency, since it is the whole argument: `BLOB`s were survivable
*with* the 256 KiB cap. It is our own instruction that makes them untenable.

The costs are real and are accepted here rather than discovered later:

- **The store is now two things that can disagree** — rows in `network.db`,
  bytes in `bodies/`. Every failure below is a form of that.
- **Filenames are generated before capture starts**, not derived from the row
  `id`: the body streams to disk before the `INSERT` that would assign one.
  Mode `0600`, directory `0700`.
- **A file may outlive its row, and a row may outlive its file.** A crash
  mid-capture orphans a file (no row ever written); a user deleting `bodies/`
  strands a row. Both must be survivable: readers treat a missing body as
  **absent, not an error**, and retention sweeps orphans (D2). A dangling row is
  not a corruption to repair, it is a body we no longer have.
- **A capture can be partial** — the client hangs up mid-stream, the disk fills.
  The row records what was actually captured; a short file is not a decode
  failure and must not be reported as one.

No body redaction, either: a body is arbitrary JSON, source code and prose with
no key names to match on, so redaction there is unreliable in a way header
redaction is not — it would give the appearance of safety while missing most
secrets, and mangle the record we are keeping it for.

**The Jul-5 code already met the load-bearing constraint, and D1 keeps its
shape.** It did not buffer-then-forward: it wrapped the response in
`io.TeeReader(resp.Body, capture)` where `capture` was a `bodyCapture{buf,
total, max}` writer, so bytes reached the client as they passed and
`ResponseSize = capture.total` was the **true** size, not the captured prefix.
The constraint this ADR calls load-bearing was therefore already satisfied by
working code. D1 is a **small delta on it**, not a rewrite: keep the tee, keep
`bodyCapture`'s shape (a writer on the tee that owns the sink and counts the
total), and swap the bounded `bytes.Buffer` for a file sink. Anything that
re-derives the capture path from scratch has thrown away a correct answer.

The contract, restated so it survives the next rewrite:

- **Capture tees, and must never buffer a response before forwarding it.**
  This is the load-bearing constraint. The model turns are **SSE**
  (`Content-Type: text/event-stream`, measured) and one streamed for 14
  seconds. Buffering a response to store it would make the agent wait for the
  whole stream — the exact reason SSE appears to hang through Burp, which
  buffers. Bytes go to disk as they pass, or interactive token streaming dies.
- **The total is counted on the tee, never inferred from the sink.**
  `ResponseSize` must be the bytes that crossed the wire, independent of what
  the sink kept or dropped. The Jul-5 code had this right (`capture.total`);
  say it here so a file sink does not tempt someone into `stat`ing the file.
- **What is stored is a normalized capture, not verbatim wire bytes.** The body
  is stored after transfer-decoding (chunk framing removed) and after
  content-decoding (decompressed), because a gzipped blob is not a transcript
  anyone can read. The file holds raw bytes and is never assumed to be UTF-8.
  This is a deliberate readability choice and the ADR will not call it
  "verbatim".
- **Bytes, not `string`. This is the first thing Jul-5 got wrong.** It stored
  bodies as `string(raw)` into a **`TEXT`** column. Any non-UTF-8 body — an
  image, a tarball, a protobuf, a failed gzip decode — is corrupted on the way
  in: invalid sequences are mangled and the original bytes are unrecoverable.
  The file sink makes this structurally hard to reproduce (files hold bytes),
  but the lesson generalizes to every column: a body is a byte string, and a
  type that cannot say so will silently lie about what was captured.
- **Decoding is best-effort; the bytes are not.** If a body cannot be decoded
  safely or at all — unsupported encoding, corrupt stream, or an expansion ratio
  that smells like a decompression bomb — the **raw encoded bytes are stored**
  with an `encoding_raw` marker, and decoding is abandoned. Raw fallback is the
  rule for every decode failure, not a special case: decoding is a readability
  convenience, and it must never become a reason to drop bytes we promised to
  keep. Nothing is ever partially decoded and truncated.
- **The `encoding_raw` marker is not hypothetical — its absence is a live bug in
  a database that exists. This is the second thing Jul-5 got wrong.** The gzip
  path (`2f3d28ce`) decoded from `capture.buf`, which held only the first 256 KB
  of the **compressed** stream. Any gzip response larger than that leaves a
  truncated stream, so `gzip.NewReader` / `io.ReadAll` errors — and the code
  only assigns `raw = decoded` when `readErr == nil`. On error it falls through
  and stores **the raw compressed bytes**, as `TEXT`, **with no marker at all**.
  The row is indistinguishable from a successfully-stored plaintext body; the
  viewer renders gzip framing as garbage, which is the exact symptom `2f3d28ce`
  set out to fix and did not, for every body over the cap. Both bugs compound:
  the corrupting `string()` cast lands on the one path that most needs raw
  bytes. D1's rule — decode from the *whole* body, and mark the fallback —
  exists because this failure has already shipped, not because someone imagined
  it.
- **`maxBodyScan` (1 MiB) stays exactly as it is.** It is the *policy scan*
  window, unchanged by this ADR: it governs what the DSL inspects, not what is
  stored. Note the resulting asymmetry, since it will surprise someone: a 5 MB
  request is now stored whole but still only policy-scanned over its first
  1 MiB. Response bodies are stored but **not** policy-inspected at all today.

### D2 — Retention: 90 days or 1 GB, whichever comes first — as a target, not a guarantee

Eviction drops oldest rows when **either** bound is crossed. Both are
configurable under `network:` in policy.yaml.

1 GB is the bound that will usually bind: at ~1.3 MB for a short session, and
long sessions growing superlinearly (each turn resends the conversation), heavy
use reaches it well before 90 days.

**The budget spans the DB and `bodies/` together** — the directory is the
dominant term, and a cap that only counted rows would measure the wrong thing.

**The cap is a logical target and the ADR will not claim otherwise.** But moving
bodies out of SQLite (D1) dissolves most of what made this hard, and the ADR
should say so plainly rather than keep the scar tissue:

- **Body bytes are reclaimed by `unlink`, immediately and completely.** The
  `auto_vacuum` problem below applied to *bodies in pages*; bodies are not in
  pages any more. Eviction of a body is a file delete, and the space comes back.
- **The `auto_vacuum` / `VACUUM` migration is no longer required.** It was the
  price of storing MB-scale blobs in a store that never returns pages to the
  filesystem. `network.db` is now metadata plus paths, so it stays small and
  the reclamation problem shrinks with it. The measured gotcha is retained
  below because it is true and someone will otherwise rediscover it — not
  because this design still needs it.
- **It does not shrink to nothing, and this is the honest remainder:** URLs and
  query strings carry credentials too (D4), and a `DELETE` leaves those in
  freelist pages until overwritten. "Evicted" still means "unreachable by
  query", not "gone from the device" — now for metadata rather than for
  transcripts. `wal_checkpoint(TRUNCATE)` is still wanted on the eviction path.
- **Deleting a body file does not scrub the device either.** `unlink` returns
  the blocks; it does not overwrite them, and on a CoW or log-structured
  filesystem, or an SSD's FTL, the old bytes may persist. Nothing here is a
  secure-erase guarantee and must not be described as one.

Retained, because it is measured and true — for whoever later reconsiders
storing anything large in this DB. On the real `network.db`, `auto_vacuum = 0`,
and setting the pragma alone leaves it at `0`; it only takes effect after a full
rebuild:

```
pragma auto_vacuum=INCREMENTAL           -> 0   (no effect)
pragma auto_vacuum=INCREMENTAL; VACUUM;  -> 2   (a one-time rebuild)
```
- **One huge body can evict everything else, and can defeat the cap outright.**
  With no per-body cap (D1), a single multi-GB download exceeds the budget by
  itself and pushes older sessions out. Worse, a body larger than the 1 GB
  target leaves the store **over the cap even after every other row is gone**:
  eviction could only get under it by deleting the row it just wrote, which D1
  forbids. So the byte target is best-effort by construction, and eviction must
  stop when there is nothing left to drop rather than eat the current session.
  Accepted: it is rare (observed maximum 1.3 MB), and capping bodies to protect
  history would trade a certain loss for a hypothetical one. Revisit with real
  numbers, not a guess. **Under D1 this costs disk, not availability** — the
  daemon no longer holds the body in memory, so the failure is a full disk and a
  thinned history rather than a dead policy enforcer.
- **Eviction order is row first, then file.** The reverse strands a row pointing
  at bytes that are gone; this way a crash in between leaves an orphan file,
  which the sweep below reclaims. The DB is the index of truth, and it should
  never claim a body it cannot produce.
- **Orphan sweep.** A crash mid-capture leaves a file no row references. Nothing
  will ever read it and nothing will ever evict it by age, so retention must
  reclaim files in `bodies/` with no referencing row. Without this, the leak is
  unbounded and invisible — bytes we promised to bound, held forever, by a path
  no query can reach.

Eviction emits an audit event (rows, bytes, cutoff — never body content), and so
does a retention **config change**, since lowering retention destroys history
(AGENTS.md: a state change that is user-visible is audit-worthy).

### D3 — The agent may not read the store — a mediation control, not a boundary

`network.db`, **its sidecars** (`-wal`, `-shm`, any rollback journal, any vacuum
temp file), **and the `bodies/` directory** must be unreadable by the agent.
Shipped in the same change as D1.

**`bodies/` is where the transcripts actually live now (D1), so it is the more
important half of this rule, not an addendum.** Denying `network.db` while
leaving `bodies/` readable would protect the index and publish the content — a
deny rule that reads as complete and is worthless. Note the shape difference:
the store names are *files*, `bodies/` is a *directory*, and Linux's
`AgentjailReadDeniedNames()` skips names when enumerating `~/.agentjail`'s
children. Skipping the name grants nothing under it, so the subtree is denied by
the allowlist's default — but that is a claim to **test**, not to assume, since
it is the first directory the mechanism has had to cover.

The two backends get there by **different mechanisms**, and saying "the shared
contract covers both" would be self-serving:

- **Linux** enumerates `~/.agentjail`'s children and skips the names in
  `AgentjailReadDeniedNames()`. The store names go there. This is the actual
  change — Linux is where the exposure is.
- **macOS** is already covered, but by a *different* rule: `sensitiveReadPaths`
  denies the whole `~/.agentjail` subtree. Nothing to add; something to protect
  (see the invariant below).

**This is a sandbox mediation control, not an OS account boundary, and the
difference is the whole caveat.** The agent runs as the *same uid*: file modes
are not protecting anything here. D3 holds only while the sandbox is actually
applied, and is defeated by:

- Landlock unsupported / older kernel → the shield fails open by design;
- `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` — an existing, documented escape hatch;
- macOS without `sandbox-exec`, same fail-open shape;
- any other process running as the user — a shell, an editor, a backup agent;
- a bug in applying Landlock after `nsenter` (that path is young — AGE-166).

So D3 raises the cost for a *contained* agent. It does not make the file safe.
Anyone reading this ADR to decide whether bodies-on-disk is acceptable should
weigh the second sentence, not the first.

**Invariant (needs a test, not a comment):** no generated sbpl profile may
contain a later `file-read*` allow covering `~/.agentjail`, and Linux must not
grant a recursive read of `~/.agentjail`. macOS's protection today rests on
last-match ordering against `(allow default)`; a future carve-out could silently
reopen it.

### D4 — Headers stay redacted, and that changes nothing about the DB's class

The header redaction from AGE-232 (`internal/redact`) stays: it is built, costs
nothing, and keeps the metadata-only views clean.

It must not be read as mitigation. With raw bodies beside them — and credentials
also appearing in URLs, query strings and response headers — `network.db` is a
credential-bearing file whatever we do to the `Authorization` column. D4 is
tidiness, not defence.

### D5 — The launch notice must say we record, and this is disclosure, not consent

ADR 0077 D4 requires every launch to state its posture and forbids claiming to
observe while decrypting. Extended: the banner said "agentjail is decrypting
this agent's HTTPS"; it must now also say it is **recording** it, with the
retention window.

**ADR 0077's default-on argument does not carry over by inheritance.** That
argument rested on two legs — the DSL cannot reach HTTP(S) without interception,
*and* we decrypt without keeping a transcript. This ADR removes the second leg.
The first still stands, which is why the default is not reopened here — but
saying the argument "survives" would be wishful. A banner is **disclosure**;
consent to decrypt-in-memory is not consent to a 90-day transcript of your
source code. **AGE-171 (default-on) must be argued afresh with this ADR in
hand**, not treated as already decided.

## Consequences

- **The product does what it claimed.** AGE-79's "complete visibility" and
  AGE-111's session replay become buildable. This is the feature the tunnel
  exists for. Note the split: restoring the orphaned Network tab (`6ceecc3`)
  brings back request/response **metadata**, and needs nothing from this ADR.
  Only **bodies** depend on D1 — so the two should not be sequenced as one
  thing, and a body-less tab is worth shipping first. The rescued Burp-style
  viewer (`6ef49e02`, `19ca0c9a`) already renders bodies when the rows carry
  them, so the UI half of D1 is largely **restoration**; the work is in the
  capture path and the two bugs, not the frontend.
- **`~/.agentjail/bodies/` becomes the most sensitive thing agentjail writes** —
  source code and credentials, on disk, unencrypted, and now in **plain files
  rather than inside a database**. That is a real ergonomic downgrade for
  secrecy: `grep -r` over the directory yields secrets with no SQLite client and
  no schema knowledge, where a `BLOB` at least demanded both. D3 closes the
  contained-agent path on Linux (macOS already had it). Encryption at rest is
  **not** in scope and would be its own ADR; until then the honest summary is
  "0600, a deny rule, and the user's disk".
- **Captures are unshippable.** Neither `network.db` nor `bodies/` can be
  attached to an issue, shared for support, or committed — sharper than the
  existing testbed-recording rule. The baseline fixture's leak gate checks
  *headers* and does not make a body capture publishable. Any UI export needs a
  warning, and bug-report tooling must never collect either by default. Note
  that a loose directory of files is far easier to sweep up by accident — into
  a backup, a sync client, an editor's search index — than a single DB file was.
- **"Nothing legitimate regresses" would be too strong.** D3 breaks any
  in-sandbox reader of the store: an agent debugging its own traffic, an MCP
  tool reading `~/.agentjail` for observability, a future in-sandbox viewer.
  It also creates an obligation: **the UI and CLI must not be launched under the
  shield** if they need network history.
- **Recording failure needs a stated posture** (ADR 0077 D5's shape, applied to
  storage): if the store cannot be written — disk full, eviction failing,
  checkpoint failing — the tunnel **keeps running and interception stays on**,
  and says so loudly. Policy enforcement must not depend on the recorder: the
  DSL evaluates from the in-memory body regardless. Today an unopenable
  `network.db` disables interception entirely (`startTunnel`); once the store is
  the product record that coupling is wrong in both directions and must be
  revisited. **The failure is audited, not only printed**: recording failure is
  precisely the moment `network.db` cannot hold its own evidence, so the record
  that it failed has to live somewhere else (`audit_log`, in `agentjail.db`).
- **Eviction is new code on a store that only ever grew.** A bug there deletes a
  user's history. It needs tests — under WAL, with a concurrent writer — not a
  cron and hope.
- **Third-party data.** Transcripts will contain other people's confidential
  data, regulated data, and vendor responses, not just the user's own. That is a
  legal/compliance surface this project has not had before, and it should be
  documented for users rather than discovered by one.

## Related

- Supersedes [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md)
  S-C2 (bodies not persisted). The rest of 0076 stands — including **S-C1**
  (in-memory CA key), whose reasoning ("the agent shares the host uid, so a 0600
  file is readable by it") is exactly what D3 applies to the store we are about
  to fill with secrets.
- [ADR 0077](./0077-tunnel-mitm-default-and-consent.md) — D4 (announce the
  posture) extends to recording; see D5, which also re-opens AGE-171's basis.
- [ADR 0032](./0032-phantom-credentials.md) — "never log credential values"
  governed headers; this ADR consciously exempts bodies and says why (D4).
- [ADR 0034](./0034-platform-backend-shared-contract.md) — the two backends
  reach D3 by *different* mechanisms (Linux: `AgentjailReadDeniedNames()`;
  macOS: the pre-existing whole-subtree deny), so this is one contract with two
  translations, and the sbpl invariant is what keeps macOS's translation honest.
- **`rescue/burp-ui-2026-07-05`** — the stranded prior art this ADR is
  restoring, not inventing: `36ba7ab2` (body capture, the correct tee),
  `2f3d28ce` (gzip, and the unmarked-fallback bug), `6ef49e02` / `19ca0c9a` /
  `0a014948` (the `/network` viewer). Read it before implementing D1.
- AGE-79 (the visibility goal), AGE-111 (session tracing/replay — the consumer),
  AGE-232 (header redaction, retained by D4), AGE-171 (default-on — to be
  re-argued, see D5).

## Implementation invariants

For the ticket that builds this, so they are not rediscovered:

- [ ] **Start from `rescue/burp-ui-2026-07-05`, do not rewrite the capture
      path.** `36ba7ab2` already tees correctly. The delta is: `bodyCapture`'s
      `bytes.Buffer` becomes a file sink, `total` stays as-is, the two bugs
      below get fixed. A from-scratch capture path is a red flag on review.
- [ ] **Bodies are `[]byte` end to end, never `string` into `TEXT`** — the
      Jul-5 corruption bug. A non-UTF-8 body (image, tarball, protobuf) must
      round-trip byte-identical; assert that, not that it "renders".
- [ ] **Content-decoding reads the whole body, not the sink's prefix**, and a
      failed decode stores raw bytes **with the `encoding_raw` marker set** —
      the Jul-5 gzip bug, which stored compressed bytes unmarked. Test with a
      gzip response larger than any buffer and assert the marker, since the
      unmarked failure is invisible by construction.
- [ ] Deny `network.db`, **every sidecar**, **and `bodies/`**; test that a
      shielded agent can read none of them, on **both** OSes. `bodies/` is a
      directory and the first one this mechanism covers — assert the subtree,
      not just the name.
- [ ] No recursive read grant on `~/.agentjail` (Linux); no later sbpl
      `file-read*` allow covering it (macOS) — asserted by a profile test.
- [ ] Capture tees; it must NOT buffer a response before forwarding. Test with
      a real SSE endpoint and assert first-byte latency is unchanged — this is
      the constraint that keeps interactive streaming alive.
- [ ] **Peak memory does not scale with body size.** The point of D1's file
      sink. Test with a body far larger than any plausible buffer and assert
      the daemon's memory does not track it — otherwise the BLOB design has
      been reintroduced by accident.
- [ ] Body files are `0600` in a `0700` directory, named before capture starts.
- [ ] A missing body file is **absent, not an error**: a row whose file was
      deleted must still list and still render.
- [ ] Orphan sweep reclaims `bodies/` files with no referencing row; tested by
      simulating a crash mid-capture.
- [ ] Eviction deletes the row before the file; budget counts DB + `bodies/`;
      tested with a concurrent writer. `wal_checkpoint(TRUNCATE)` on the
      eviction path. Audit event with counts, never content.
- [ ] Policy evaluation must not regress when the store is unavailable; the
      failure is audited to `agentjail.db`, not just printed.
- [ ] `maxBodyScan` (1 MiB policy window) is untouched by this work.
- [ ] `request_size` / `response_size` must be the **true** sizes. The scan
      window silently capped `request_size` at 1048577 for every larger upload
      (fixed, AGE-243) — D2 budgets against these numbers, so a lie here is a
      retention bug, not a cosmetic one.
