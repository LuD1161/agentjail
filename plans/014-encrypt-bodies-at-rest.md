# Plan 014 — Encrypt captured bodies at rest, grouped per session

**Status:** Proposed design, round 5. Reviewed adversarially by Codex four
times; every P0 from every round is addressed. **Not implementation-ready until §9.1 is
answered by a human** — that question decides whether to build this at all.
**Builds on:** ADR 0092 D1 (bodies are files under `~/.agentjail/bodies/`), D3
(the agent may not read the store), D2 (retention), D4 (headers redacted, and
why that is not mitigation).

## 0. The proposal

Store captured request/response bodies **encrypted at rest**, grouped **per
session**, with markers in `network.db` so the UI can locate and **stream** each
body without loading it whole.

## 1. What encryption buys — stated narrowly, because the wide claim is false

**The agent runs as the same uid as agentjail.** ADR 0076 S-C1 already reasoned
from this: the MITM CA key is never written to disk *because* a 0600 file is
readable by the agent sharing our uid. The same applies to a body key. **Any key
agentjail can read non-interactively, the agent can read too.**

- **Encryption does NOT protect against the sandboxed agent.** D3 does, and D3
  is a *mediation control, not a boundary*.
- **It does NOT make a copied capture "useless".** An earlier draft of this plan
  said so; that was wrong, and the reason matters: **`network.db` metadata stays
  plaintext** — hosts, full URLs, query strings, timing, sizes. ADR 0092 D4 says
  outright that **credentials appear in URLs and query strings**. So a thief with
  the DB and no key still gets every endpoint the agent touched, every token in a
  query string, and a timing profile. Encrypting bodies while leaving that in
  cleartext is a *partial* measure, and §9.1 asks whether partial is worth it.
- **What it actually buys:** the body transcripts — source code, `.env`
  contents, model conversations — survive an accidental copy. Backups, sync
  clients, editor search indexes, a support bundle, an issue attachment. That is
  the ADR 0092 "captures are unshippable" problem, and it is real.
- **It is not general stolen-disk protection.** That is FDE's job. Against a
  cold disk this helps only insofar as the keychain material is not on the same
  disk in a usable state.

**Precedent.** Chrome encrypts cookies with a key from the OS keychain
(Keychain / Secret Service / DPAPI). It is well established this is **not** a
defence against same-uid infostealers — they ask the keychain and it answers.
Burp and mitmproxy do not encrypt saved flows at all. Real protection (1Password
et al) needs a **human-supplied secret and a lock**, which a background recorder
cannot have.

**One place the flat claim under-sells macOS:** Keychain items can carry ACLs,
user-presence requirements, and code-signing identity constraints. If agentjail
ever ships signed binaries, macOS *can* meaningfully restrict which binary gets
the key — that is a stronger property than Linux's Secret Service offers, and it
should not be flattened away in the shared contract (ADR 0034: name your
exceptions).

**And one live bypass the at-rest design cannot fix alone:** once the UI streams
*decrypted* bodies over unauthenticated loopback, a same-uid process does not
need the key — it needs `curl`. **This design is therefore gated on the UI auth
decision (plan 013 §6)**, not merely adjacent to it. Shipping at-rest encryption
while the UI serves plaintext bodies to anything that can reach the port is
theatre with extra steps.

## 2. Layout — and the two things the current code cannot do

The proposal was `~/.agentjail/<session_id>/bodies`. **That would expose every
prior session's bodies to the agent.** Verified in `shield_linux.go`: the deny
does `os.ReadDir(~/.agentjail)` **at launch**, then *allows* each child except a
**static** name set, granting directories recursive `roAccess`. Session-id dirs
are not in that set.

**Use `~/.agentjail/bodies/<session_id>/`.** `bodies` is one static name already
denied (`7847c21`); the whole subtree is skipped and never granted.

```
~/.agentjail/
  network.db                 (denied by name; metadata still plaintext — §1)
  bodies/                    (denied by name — one entry covers everything below)
    <session_id>/
      <body_id>.raw.enc      encrypted wire bytes (stage 1, §4)
      <body_id>.body.enc     encrypted decoded copy (stage 2) — 0600, 0700 dir
```

**Blocker A — the traversal guard forbids this layout.** `BodyStore.Open` today:

```go
if rel != filepath.Base(rel) || strings.HasPrefix(rel, ".") { ... reject }
```

Any `/` is rejected, so `<session_id>/<id>.body` cannot be stored or read. The
guard must be **widened precisely**: accept exactly `<safeSessionID>/<safeBodyID>.body`
where both components match a strict charset (hex/ULID), reject `..`, reject
absolute paths, **reject symlinks at every component** (`O_NOFOLLOW` / `Lstat`),
and the orphan sweep must never follow links. The DB is same-uid writable outside
the sandbox, so a stored path is untrusted input — widening this guard is a
security change, not a plumbing one.

**Blocker B — `session_id` is a column nothing populates.** Grep finds only the
struct field, the INSERT and the scan. Per-session grouping needs a session id
wired from the shield through `tunnel_shield_linux.go` into the `RequestLog`
first. Its own commit.

## 3. The file format — because "use age" is not a design

ADR 0092 D1's invariant is that **peak memory must not scale with body size**
(128 MiB body, < 8 MiB heap, asserted). Whole-file AES-GCM `Open` breaks that
outright: GCM authenticates the whole ciphertext, so it cannot yield a byte
before it has all of it. That reintroduces the OOM that made us choose files over
`BLOB`s, and kills UI streaming.

**Chunked AEAD is required.** But the earlier "adopt `filippo.io/age` STREAM"
was not a design and contradicted the Range claim in the same document: age's
public shape is a *sequential* file-encryption API, not a `ReaderAt`. Pick by
API shape, explicitly:

- **Sequential-only** (age as-published): HTTP `Range` becomes
  decrypt-and-discard from byte 0. Correct, simple, and O(offset) per request —
  acceptable if the UI only ever streams from the start, unacceptable for
  scrubbing a large body.
- **Seekable, chunk-granular**: needs a format we specify. Recommended, given the
  UI wants Range.

**If we specify it, it gets a versioned header and a security review** — that is
the price of not using an off-the-shelf API, and AGENTS.md's crypto rule
(stdlib `crypto/*`) makes hand-rolling the *construction* the deviation that
needs the ADR.

**The header splits in two, and the split is load-bearing.** Rotation rewrites
the key-wrap fields; if chunk AAD covered them, **every chunk would fail
authentication the moment we rotated**. So:

```
magic "AJBODY\0" | version u8
| imeta_len u32 | imeta[imeta_len]      <- IMMUTABLE
| emeta_cap u32 | emeta_len u32 | emeta[emeta_len] | pad[emeta_cap-emeta_len]
|                                        ^- MUTABLE, FIXED-SIZE SLOT
| chunk[0..n]                             (starts at a fixed offset, always)

imeta — immutable for the file's life; bound into EVERY chunk's AAD:
  data_alg u8            AEAD over chunks (e.g. AES-256-GCM)
  chunk_size u32
  file_id 16B            random, unique per file
  side u8                request | response
  session_id 16B
  encoding_raw u8        what D1 decided is inside (decoded | raw)
  plaintext_len u64      ^0 if unknown at header-write time

emeta — the key envelope; REWRITTEN IN PLACE on rotation, never in chunk AAD:
  kek_alg u8             KEK algorithm + version
  kek_id  varbytes       which KEK; NOT a u8 — rotation space must not be
                         capped by the format
  wrapped_dek varbytes   the DEK, wrapped under that KEK
```

- **Chunk AAD = `imeta` bytes ‖ chunk_index ‖ final_flag.** Immutable fields
  only, so rotation cannot invalidate a single chunk.
- **`emeta` is authenticated by the key-wrap itself**, not by the chunks — an
  AEAD wrap whose own AAD binds `file_id` and `side`. That is what stops a
  same-uid writer lifting a `wrapped_dek` from one file into another: the wrap
  will not open against the wrong `file_id`. `emeta` needs no chunk-level
  protection because a forged `wrapped_dek` simply fails to unwrap.
- **`emeta` is a fixed-size slot, not a variable field, and that is what makes
  "rewrite in place" true.** `emeta_cap` is chosen at create time (512 B is
  ample for any KEK id + wrapped DEK) and never changes, so the chunk region
  always begins at the same offset. A rotation writes a new envelope into the
  slot and pads; chunk offsets cannot shift. Without the cap, a rotated KEK with
  a longer `kek_id` would move every chunk and "cheap rewrap" would be a
  whole-file rewrite — the thing the envelope exists to avoid.
- If an envelope ever exceeds `emeta_cap`, that is a **format v2**, not a silent
  re-lay-out. Fail loudly.
- Rotation therefore rewrites the `emeta` slot and nothing else. Bodies are
  untouched.

- **Envelope, one model, not two.** A **random per-file DEK** encrypts the
  chunks. The DEK is **wrapped under the keychain-backed KEK** and stored in the
  header (`wrapped_dek`). `kek_id` says which KEK wrapped it. **Rotation rewraps
  the header's DEK; bodies are never re-encrypted.** (An earlier draft said
  per-file key = `HKDF(master, file_id)` here and KEK/DEK in §5 — those are
  incompatible designs: HKDF-from-master forces re-encrypting every body to
  rotate. The envelope wins because rotation must be cheap.)
- **Nonce** = chunk index counter, under a per-file DEK. Never reused: the DEK
  is unique per file by construction, so the counter cannot collide across files.
- **AAD binds `imeta` + chunk index + final-chunk flag** — immutable header
  fields only, never mutable DB columns (the DB is same-uid writable, so binding
  AAD to DB values would let a same-uid writer re-point a row and pass auth) and
  never `emeta` (see the split above — that would break rotation).
- **Final-chunk marker mandatory**, or truncation is silently a valid file.
- **Range** = seek to `floor(offset/chunk_size)`, decrypt forward. Chunk
  granularity, not byte. Say so; do not promise byte seeking.

## 4. Never write plaintext to disk — the pipeline, not a wrapper

**This is the finding that would have sunk the feature.** `decodeGzip` today
calls `b.createFile()` and `io.Copy(out, gr)` — it writes a **decoded plaintext
body file** to disk. Wrapping encryption around `Finish` would mean a complete
plaintext transcript exists on disk, briefly, exactly when the point of the
feature is that it should not.

**But a single `gzip → AEAD → file` pipeline is also wrong**, and this is the
subtler trap: ADR 0092 D1 requires that **any** decode failure keeps the **raw
encoded bytes** with an `encoding_raw` marker. A gzip stream can fail *late* —
100 MB in. If we streamed only decoded output, the raw bytes are gone by then
and D1's contract is broken: we would have neither a decoded body nor the raw
one we promised to keep.

**So it is two stages, both encrypted, plaintext never at rest:**

```
stage 1  wire bytes ──AEAD──► <id>.raw.enc        (always; this is the tee's sink)
stage 2  <id>.raw.enc ──decrypt→gunzip→AEAD──► <id>.body.enc   (decoded copy)
         success → row points at .body.enc, encoding_raw=decoded, unlink .raw.enc
         failure → row points at .raw.enc,  encoding_raw=raw,     unlink temp
```

Stage 2 streams through memory in chunk-sized pieces — decrypt a chunk, inflate,
re-encrypt — so the memory invariant holds and **no plaintext byte is ever
written to disk**. Decode is a readability convenience; it must never be a reason
to lose bytes we promised to keep (D1), and it must never be a reason to write
the plaintext we are trying to protect.

Cost, stated: capture does one extra pass over each compressed body. Accepted —
the alternative is either losing the raw fallback or writing plaintext.

Required tests: no plaintext body file remains after (a) success, (b) an early
decode error, (c) a **late** decode error, (d) a bomb-ratio abort, (e) disk full,
(f) process kill mid-capture. Cleanup on **every** failure path; the orphan sweep
must reclaim both temps and abandoned `.raw.enc` files.

## 5. Keys — envelope, not a single key

Earlier draft picked "key from the OS keychain" and stopped. That is a KEK, not
a design. Use **KEK/DEK**:

- **DEK**: per-file, random, encrypts the chunks. Stored **wrapped** in the
  file header (`wrapped_dek`, §3) — not derived, so rotation is cheap.
- **KEK**: keychain-backed, identified by `kek_id` (variable-length, §3).
- Rotation **rewraps the header's DEK in place**; bodies are never re-encrypted.
  Damage from one leaked DEK is one body.
- This is the single key model. §3's header is its authority; nothing derives a
  per-file key from a master.

| Option | Offline copy | Same-uid agent | Cost |
|---|---|---|---|
| **A. OS keychain KEK** | Yes | **No** | per-OS backend (ADR 0034), and see macOS ACL note in §1 |
| B. Key file 0600 + deny | Barely — key sits beside ciphertext | No | ~worthless; the trap |
| C. Daemon memory only | Yes | Yes, while daemon lives | **breaks D2's 90-day retention** |
| D. User passphrase | Yes | Yes | unusable for a background recorder |

**Recommend A**, with C noted as strictly stronger and rejected *because* we
promised 90-day readable retention — a deliberate trade, recorded.

**Operational semantics, all previously missing:**

- keychain **prompt/hang deadline** — a recorder must not block a request on a
  UI prompt;
- **headless Linux / CI / no Secret Service** — see §9.2;
- **corrupted or absent keychain item** — fail how?
- **backup/restore**: a restored `bodies/` without the KEK is unreadable. That
  is the feature working as designed; it must be *documented*, not discovered.
- an **audit event** when recording is disabled or degraded for key reasons
  (AGENTS.md: a user-visible state change is audit-worthy). It goes to
  `agentjail.db`, because `network.db` cannot hold its own failure.

## 6. DB markers — per side, not one column

One `body_enc` column is wrong: a row has two bodies and migration or failure can
leave **one encrypted and one legacy**. Use per-side markers (D1 already set this
precedent with the typed `EncodingRawSides` enum), or a `network_bodies` table
keyed by (request_id, side). Prefer the table if the UI wants per-body metadata —
it also makes retention and the orphan sweep joinable instead of string-matched.

**Three sizes, currently conflated as one:**

| | meaning | who needs it |
|---|---|---|
| wire size | bytes on the wire (compressed) | D2 budget, stats, `response_size` today |
| stored plaintext size | after gzip normalization | **the UI's Range math** |
| ciphertext size | file on disk | D2's disk accounting |

`request_size`/`response_size` are **wire** sizes. Range against them is wrong
for any gzip-normalized body. Store the plaintext size explicitly.

## 7. Migration — the dangerous part

Existing plaintext bodies (D1 shipped in `30aa449`) must be migrated. Per body:
stream plaintext → chunked-AEAD temp → `fsync` → atomic rename → update the DB
marker **after** the file lands → only then unlink the plaintext. Crash recovery
must handle: legacy plaintext, encrypted complete, encrypted temp, and a DB
marker that disagrees with the file — **without data loss and without silently
falling back to plaintext**. A marker claiming encrypted over a plaintext file is
the worst outcome; it must be impossible or loudly detected.

Mitigating fact: D1 is **inert** (`Bodies` is nil at the only construction site),
so if this lands before D1 is wired, there is nothing to migrate. **That is an
argument for sequencing this before switching capture on.**

## 8. Commit breakdown

1. `feat(mitm): carry the session id into the request log` — §2 Blocker B.
2. `fix(mitm): allow exactly session/body paths, reject symlinks` — §2 Blocker A.
3. `feat(mitm): group bodies per session` — layout, still plaintext.
4. ADR: the crypto deviation, the file format, the KEK/DEK model; `make licenses`.
5. `feat(mitm): chunked AEAD body format` — split imeta/emeta header, random
   per-file DEK wrapped under the KEK, counter nonce, final-chunk marker, AAD
   over `imeta` only. Tests: round-trip, truncation, chunk reorder, cross-file
   `wrapped_dek` swap, **rotation leaves every chunk verifiable**, and **the D1
   memory assertion re-run on the encrypted path** (the test that catches a
   whole-file `Open`).
6. `feat(mitm): two-stage raw-then-decoded encrypted capture` — §4, with the
   no-plaintext-remains tests including a **late** decode failure. **Must not
   land after 5 as a wrapper around Finish.**
7. `feat(mitm): KEK from the OS keychain` — per-OS implementor, one contract.
8. `feat(store): per-side markers + plaintext sizes` + migration (§7).
9. `feat(ui): stream bodies with Range` — after 013's detail panel and its auth.

## 9. Open questions — answer before building

1. **Is partial encryption worth it?** Bodies encrypted, `network.db` metadata
   plaintext — including URLs and query strings that D4 says carry credentials.
   Options: (a) accept, document the leak; (b) encrypt metadata too (SQLCipher =
   a large dependency and its own ADR); (c) do neither and rely on 0700 + D3 +
   "don't back up `~/.agentjail`". **This is the decision the rest depends on.**
2. **No keychain available** (headless Linux, CI, no Secret Service): fail closed
   (refuse to record) or plaintext with a loud notice? A **silent** plaintext
   fallback is the worst outcome — the marker implies protection that isn't
   there. ADR 0092's recording-failure posture says the tunnel keeps running and
   says so loudly; this should match it.
3. **Rotation policy** (the model is settled — rewrap `emeta`, §3): when do we
   rotate, eagerly or lazily, and what happens to a body whose rewrap fails —
   leave it on the old KEK, or treat it as lost?
4. **macOS has no tunnel today** (AGE-149), so this ships Linux-first. Write the
   keychain contract now or when macOS lands? ADR 0034 says the contract is
   shared and drift is a bug — but a contract with one implementor is also how
   `shield_linux`/`shield_darwin` drifted.
5. **Does this gate on UI auth?** §1 argues yes: at-rest encryption with an
   unauthenticated loopback UI serving decrypted bodies protects nothing against
   a same-uid reader. Sequence 013's auth first, or accept the gap explicitly.
