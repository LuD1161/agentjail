# ADR 0095: captured bodies are a chunked-AEAD envelope, and capture is two-stage

**Status:** Accepted — implements [plan 014](../../plans/014-encrypt-bodies-at-rest.md)
§3 and §4, builds on [ADR 0092](./0092-persist-request-bodies.md) D1.

## Context

AGENTS.md says crypto is stdlib `crypto/*`. Specifying a **file format and an
AEAD construction** is the deviation that rule exists to catch, so it needs a
recorded decision. Three constraints force it.

**1. Whole-file AEAD breaks the D1 memory invariant.** ADR 0092 D1 asserts peak
memory must not track body size (128 MiB body, < 8 MiB heap, tested). GCM
authenticates the whole ciphertext, so `Open` cannot yield a byte before it has
every byte. That reintroduces the agent-triggerable OOM that made us choose
files over `BLOB`s in the first place, and it kills UI streaming. Chunked AEAD
is not a preference; it is the only shape that satisfies D1.

**2. An off-the-shelf sequential API is the wrong API shape.** `filippo.io/age`
STREAM is published as sequential file encryption, not a `ReaderAt`. The UI
wants HTTP `Range` over large bodies; against a sequential API that is
decrypt-and-discard from byte 0, O(offset) per request. We accept specifying a
format in order to get chunk-granular seeking. We do **not** promise byte
seeking: `Range` seeks to `floor(offset/chunk_size)` and decrypts forward.

**3. Rotation must be cheap, and the naive binding makes it impossible.** If a
chunk's AAD covered the key envelope, rewrapping a DEK under a new KEK would
invalidate **every chunk in the file**. Re-encrypting every body to rotate a key
is not rotation, it is a migration. This was the P0 an adversarial review found
in an earlier draft, and it is the reason the header splits in two.

Encryption's benefit is narrow and plan 014 §1 states it: the agent runs as our
uid, so any key we can read non-interactively it can read too. This protects
body transcripts against an *accidental copy* — a backup, a sync client, a
support bundle. It is not a defence against the sandboxed agent (D3 is), and
`network.db` metadata stays plaintext.

## Decision

**D1 — The AJBODY container, header split into an immutable and a mutable half.**

```
magic "AJBODY\0" | version u8
| imeta_len u32 | imeta[imeta_len]                  <- IMMUTABLE
| emeta_cap u32 | emeta_len u32 | emeta | pad       <- MUTABLE, FIXED-SIZE SLOT
| chunk[0..n]                                        (fixed offset, always)
```

`imeta` holds `data_alg`, `chunk_size`, a random 16-byte `file_id`, `side`,
`session_id`, `encoding_raw` and `plaintext_len`. It is immutable for the file's
life. `emeta` holds `kek_alg`, a **variable-length** `kek_id` and the
`wrapped_dek`; rotation space must not be capped by the format.

**D2 — Chunk AAD is `imeta ‖ chunk_index ‖ final_flag`. Immutable fields only.**
Never `emeta` (that is D3's whole point), and never a mutable DB column: the DB
is same-uid writable, so binding AAD to DB values would let a same-uid writer
re-point a row and still pass authentication. The nonce is the chunk index
counter under a per-file DEK, so it cannot collide across files. The
**final-chunk flag is mandatory** — without it, truncating the tail yields a
file that still authenticates, and short data reads back as success.

**D3 — `emeta` is a fixed-size slot (`emeta_cap` = 512 B), rewritten in place.**
This is what makes "cheap rewrap" true rather than aspirational: chunk 0 sits at
a constant offset, so a rotation writes a new envelope into the slot and pads.
Without the cap, a longer `kek_id` would move every chunk and the envelope would
buy nothing. **An envelope past the cap is a format v2 and fails loudly** — it
is never a silent re-lay-out.

**D4 — Envelope keys: a random per-file DEK, wrapped under a keychain-backed
KEK.** Not `HKDF(master, file_id)`: derivation forces re-encrypting every body
to rotate, which contradicts D3. The **key-wrap's own AAD binds `file_id` and
`side`**, so a same-uid writer cannot lift a `wrapped_dek` from one file into
another — it will not open against the wrong file. `emeta` needs no chunk-level
protection because a forged envelope simply fails to unwrap.

**D5 — The KEK arrives through a consumer-defined interface.** `mitm.KeyWrapper`
(`Wrap`/`Unwrap`) is defined in `internal/mitm` because the consumer defines the
seam (AGENTS.md). `internal/keyring` implements it per-OS against one shared
contract (ADR 0034). `MemoryKeyWrapper` is the test and bootstrap implementor
and is explicitly **not** at-rest protection.

**D6 — Capture is two-stage, and it is a pipeline, not a wrapper around
`Finish`.**

```
stage 1  wire bytes ──AEAD──► <id>.raw.enc     (always; the tee's sink)
stage 2  <id>.raw.enc ──decrypt→gunzip→AEAD──► <id>.body.enc
         success → row points at .body.enc, encoding_raw=decoded, unlink .raw.enc
         failure → row points at .raw.enc,  encoding_raw=raw
```

A single `gzip → AEAD → file` pipeline is wrong for a reason that is easy to
miss: **gzip can fail late**, 100 MB in. D1's contract is that any decode
failure keeps the raw encoded bytes with an `encoding_raw` marker. Stream only
decoded output and by the time the failure arrives the raw bytes are gone — we
would have neither a decoded body nor the raw one we promised. Two stages keep
both promises. Stage 2 runs **chunk-at-a-time in memory**, so the D1 memory
invariant holds and **no plaintext byte is ever written to disk**. The prior
`decodeGzip` wrote a decoded plaintext file; that is what this replaces.

A body with no Content-Encoding skips stage 2: its wire bytes *are* the
plaintext, so stage 1 writes `.body.enc` directly. The extra pass is paid only
by compressed bodies, as plan 014 §4 states.

## Consequences

- **We own a crypto format.** It carries a version byte and this ADR; a change
  to `imeta`'s layout is a format bump, not an edit.
- **Rotation is O(header) per body.** Rewrapping under a new KEK leaves every
  chunk verifiable and every chunk offset unmoved — both are regression-tested,
  the second with a deliberately longer `kek_id`.
- **Compressed bodies cost one extra pass.** Accepted: the alternative is losing
  the raw fallback or writing plaintext.
- **`plaintext_len` is `^0` (unknown) for every captured body.** The size is not
  known when the header is written and `imeta` cannot be amended afterwards
  without failing every chunk. Plan 014 §6 puts the plaintext size in the DB,
  which is where the UI's Range math should read it from anyway.
- **`session_id` is `SHA-256(session)[:16]`**, because the field is fixed-width
  and the session id is an opaque string.
- **Truncation, reorder and cross-file DEK swaps are detected, not tolerated** —
  a corrupted body errors rather than reading back short. Callers must treat a
  read error as "this body is gone", not "this body is empty".
- **Restoring `bodies/` without the KEK yields unreadable files.** That is the
  feature working; plan 014 §5 requires it be documented, not discovered.
- **Open questions stay open.** Plan 014 §9 gates the *feature* on the UI auth
  decision and on the headless-Linux keychain posture. This ADR settles the
  format and the pipeline only; it does not decide to turn capture on.
