# ADR 0090: network.db stores full request/response bodies, and the agent may not read it

**Status:** Proposed — supersedes the S-C2 clause of [ADR 0076](./0076-tunnel-mitm-vs-passthrough-default-posture.md), retained by [ADR 0077](./0077-tunnel-mitm-default-and-consent.md)

## Context

Two things we have written down disagree, and nothing has forced the issue yet
because no UI reads `network.db` at all (AGE-111 is unbuilt).

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
3. **Response bodies are not captured at all today.** `mitm.go` tees the
   response through a `countingWriter` to count bytes and never buffers it.
   Request bodies are buffered only to `maxBodyScan` (1 MiB); beyond that the
   remainder is streamed straight through (`io.MultiReader`). "Store bodies"
   is therefore **a proxy data-path change, not a schema change** — see D1.

## Decision

**Persist full request and response bodies -- whole, unredacted, bounded only by
retention -- and deny the sandboxed agent read access to the store.**

### D1 — Bodies are persisted whole; there is no per-body cap

`network.db` gains request and response body columns. Every body is stored in
full. **No per-body size limit**: "save everything" means everything, and the
measured traffic says a limit would be theatre — across 110+ requests of a real
Claude Code session the largest body was 1.3 MB (a web page), and the model
turns were 1.7–3.5 KB each. Only the retention bounds in D2 apply.

No body redaction, either: a body is arbitrary JSON, source code and prose with
no key names to match on, so redaction there is unreliable in a way header
redaction is not — it would give the appearance of safety while missing most
secrets, and mangle the record we are keeping it for.

Because no response capture path exists today (`mitm.go` tees the response
through a byte counter and never holds it), the capture contract has to be
pinned down rather than assumed:

- **Capture tees, and must never buffer a response before forwarding it.**
  This is the load-bearing constraint. The model turns are **SSE**
  (`Content-Type: text/event-stream`, measured) and one streamed for 14
  seconds. Buffering a response to store it would make the agent wait for the
  whole stream — the exact reason SSE appears to hang through Burp, which
  buffers. Bytes go to disk as they pass, or interactive token streaming dies.
- **What is stored is a normalized capture, not verbatim wire bytes.** The body
  is stored after transfer-decoding (chunk framing removed) and after
  content-decoding (decompressed), because a gzipped blob is not a transcript
  anyone can read. `BLOB`, not `TEXT` — bodies are not guaranteed UTF-8. This
  is a deliberate readability choice and the ADR will not call it "verbatim".
- **Decoding is best-effort; the bytes are not.** If a body cannot be decoded
  safely or at all — unsupported encoding, corrupt stream, or an expansion ratio
  that smells like a decompression bomb — the **raw encoded bytes are stored**
  with an `encoding_raw` marker, and decoding is abandoned. Raw fallback is the
  rule for every decode failure, not a special case: decoding is a readability
  convenience, and it must never become a reason to drop bytes we promised to
  keep. Nothing is ever partially decoded and truncated.
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

**The cap is a logical target and the ADR will not claim otherwise.** SQLite
does not return pages to the filesystem on `DELETE`, and the store runs in WAL
mode, so on-disk bytes can exceed the cap:

- eviction must be followed by a reclamation step. `incremental_vacuum` is
  preferable to a full `VACUUM` (which needs free space equal to the DB and
  takes an exclusive lock) — **but it is not free to adopt**. Measured on the
  real `network.db`: `auto_vacuum = 0`, and setting
  `PRAGMA auto_vacuum=INCREMENTAL` alone leaves it at `0`. It only takes effect
  after a full `VACUUM` rebuild:

  ```
  pragma auto_vacuum=INCREMENTAL           -> 0   (no effect)
  pragma auto_vacuum=INCREMENTAL; VACUUM;  -> 2   (a one-time rebuild)
  ```

  So every existing install pays the exact full-`VACUUM` cost this choice was
  meant to avoid — once, as a migration. New databases must set the pragma
  **before** table creation. Whoever implements this must not discover that
  after shipping the eviction path.
- `network.db-wal` holds recent bodies until checkpoint, so the eviction path
  needs a `wal_checkpoint(TRUNCATE)` or the WAL becomes the leak.
- **deleted rows are not destroyed** — freelist pages retain body bytes until
  overwritten. "Evicted" means "unreachable by query", not "gone from the
  device". Say so, or a user will assume a 90-day guarantee we do not provide.
- **One huge body can evict everything else, and can defeat the cap outright.**
  With no per-body cap (D1), a single multi-GB download exceeds the budget by
  itself and pushes older sessions out. Worse, a body larger than the 1 GB
  target leaves the store **over the cap even after every other row is gone**:
  eviction could only get under it by deleting the row it just wrote, which D1
  forbids. So the byte target is best-effort by construction, and eviction must
  stop when there is nothing left to drop rather than eat the current session.
  Accepted: it is rare (observed maximum 1.3 MB), and capping bodies to protect
  history would trade a certain loss for a hypothetical one. Revisit with real
  numbers, not a guess.

Eviction emits an audit event (rows, bytes, cutoff — never body content), and so
does a retention **config change**, since lowering retention destroys history
(AGENTS.md: a state change that is user-visible is audit-worthy).

### D3 — The agent may not read the store — a mediation control, not a boundary

`network.db` **and its sidecars** (`-wal`, `-shm`, any rollback journal, any
vacuum temp file) must be unreadable by the agent. Shipped in the same change
as D1.

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
  exists for.
- **`network.db` becomes the most sensitive file agentjail writes** — source
  code and credentials, in one place, on disk, unencrypted. D3 closes the
  contained-agent path on Linux (macOS already had it). Encryption at rest is
  **not** in scope and would be its own ADR; until then the honest summary is
  "0600, a deny rule, and the user's disk".
- **Captures are unshippable.** A `network.db` cannot be attached to an issue,
  shared for support, or committed — sharper than the existing testbed-recording
  rule. The baseline fixture's leak gate checks *headers* and does not make a
  body capture publishable. Any UI export needs a warning, and bug-report
  tooling must never collect this file by default.
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
- AGE-79 (the visibility goal), AGE-111 (session tracing/replay — the consumer),
  AGE-232 (header redaction, retained by D4), AGE-171 (default-on — to be
  re-argued, see D5).

## Implementation invariants

For the ticket that builds this, so they are not rediscovered:

- [ ] Deny `network.db` **and every sidecar**; test that a shielded agent can
      read none of them, on **both** OSes.
- [ ] No recursive read grant on `~/.agentjail` (Linux); no later sbpl
      `file-read*` allow covering it (macOS) — asserted by a profile test.
- [ ] Capture tees; it must NOT buffer a response before forwarding. Test with
      a real SSE endpoint and assert first-byte latency is unchanged — this is
      the constraint that keeps interactive streaming alive.
- [ ] Eviction: `wal_checkpoint(TRUNCATE)` + incremental vacuum, and the
      one-time `auto_vacuum=INCREMENTAL; VACUUM;` migration for existing DBs
      (new DBs set the pragma before table creation). Tested with a concurrent
      writer. Audit event with counts, never content.
- [ ] Policy evaluation must not regress when the store is unavailable; the
      failure is audited to `agentjail.db`, not just printed.
- [ ] `maxBodyScan` (1 MiB policy window) is untouched by this work.
