# ADR 0084-redact-secret-values: redact secrets by value, not only by key name

**Status:** Accepted

## Context

[ADR 0019-redaction-policy](./0019-redaction-policy.md) established that
`tool_input` is persisted to `decisions.tool_input_redacted`, redacted at the
store boundary, and that redaction is **key-based**: a value is replaced with
`"[redacted]"` when its *key name* case-insensitively contains `secret`, `key`,
`token`, `password`, `cred`, and friends.

ADR 0019 named this limit itself, under "Limits (acknowledged)":

> **Key-based, not value-based.** A secret placed under a key that does not
> match the substrings (e.g. `Authorization`, `X-Custom-Header`) is not
> redacted by the key rule. […] A future value-based heuristic (detect
> AWS-key-shaped strings, high-entropy blobs) can layer on top without
> changing this policy.

It also forward-referenced a value-level rule that was never written — the text
"callers that place secrets in header values should also see value-level
redaction (below)" points at a section that does not exist in that document.
This ADR is that section, arriving late.

The gap matters more than ADR 0019 assumed, for a reason that is structural
rather than exotic: **the key rule can only see a secret that someone has
labelled.** The highest-volume tool we record decisions for is `Bash`, and a
Bash tool call has exactly one interesting key — `command` — whose value is an
unstructured string. Nothing in `command` is labelled. So:

```json
{"command": "curl -H 'Authorization: Bearer sk-proj-...' https://api.example.com"}
```

The key is `command`. It matches no substring. The token is written to disk in
full. The same holds for `Write`/`Edit` (`content`), for any inline
`export AWS_SECRET_ACCESS_KEY=...`, and for `psql postgres://user:pass@host`.

ADR 0019's threat model — foot-gun, not adversary; DB is 0600, agent-unreadable
— is unchanged and still correct. This is not an exfiltration break. But that
model's *whole purpose* was "the DB is safe to browse and safe to attach to a
bug report", and a plaintext bearer token in the most common tool call defeats
exactly that. The redaction was load-bearing for a promise it did not keep.

## Decision

**Value-level redaction runs underneath the key rule, at the same boundary, on
every string scalar.** Both rules run. This is defence in depth, not a
replacement.

### Where it runs

`redactSecretsInText` in `internal/store/redact_secrets.go`, called from:

- `redactValue`'s `string` case — reaching every string scalar in `tool_input`,
  at any depth, including inside slices.
- `redactDetail` — the `audit_log` `Detail` boundary (ADR 0032-phantom-credentials).

The key rule is untouched and still wins where it fires: a key-matched value is
replaced wholesale, which correctly nukes opaque blobs that match no pattern.
`RedactToolInput` remains the sole redactor; ADR 0019's "one redactor at the
store boundary" property holds.

### What is recognised

Twelve patterns, each a shape that is self-evidently a credential:

| type | shape |
|---|---|
| `pem-private-key` | `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----` |
| `aws-access-key-id` | `AKIA` + 16 upper-alnum |
| `aws-secret` | `aws_secret_access_key` / `aws_session_token` = value |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 20, or `github_pat_` + 20 |
| `openai-key` | `sk-` or `sk-proj-` + 16 |
| `npm-token` | `npm_` + 30 |
| `slack-token` | `xox[bpcsa]-` + 10 |
| `google-api-key` | `AIza` + exactly 35 |
| `jwt` | `eyJ…` three dot-joined base64url segments |
| `url-credential` | `scheme://user:pass@host` (password only) |
| `auth-header` | `authorization` = `[scheme] value` |
| `bearer-token` | `bearer <token>` |

Matches become `[redacted:TYPE]`. The type is kept because "a bearer token was
here" and "a PEM key was here" are different facts to a human reading a replay.

**Only the secret is replaced, not the whole value.** `curl -H 'Authorization:
Bearer [redacted:auth-header]' https://api.example.com` still shows what the
agent did, which is the entire reason ADR 0019 persists `tool_input` at all.
Redaction that destroys the surrounding command would trade one failure for
another.

### Ordering and idempotency

**Pattern order is load-bearing, and the failure mode is quiet.** A narrow match
leaves a `[redacted:…]` placeholder that a later, broader pattern must not
re-match, so every key=value pattern excludes `[` and `]` from its value class.

Order runs: PEM, then the Authorization shapes, then provider tokens, then
key=value shapes. The Authorization shapes must precede the provider tokens.
The first implementation had them after, which produced:

```
curl -H 'Authorization: [redacted:auth-header] [redacted:openai-key]' https://…
```

`openai-key` redacted the token first; `auth-header` then found only a
placeholder after `Authorization:`, fell back to matching its own optional
scheme word, and redacted the literal `Bearer`. Safe, but it destroys the
context this ADR exists to preserve — and every "is the secret gone?" test
still passed. Only asserting the *exact rendered output* catches it, so the
tests do.

For the same reason `authorization` is absent from `generic-credential`'s key
list: `auth-header` handles it, and `generic-credential` would otherwise stop
at the scheme word.

Ordering alone does not give idempotency: re-running over
`Authorization: Bearer [redacted:auth-header]` reproduces the same fallback.
RE2 has no negative lookahead, so no pattern can express "the value, but not
the scheme word". The guard is therefore in code — `isNotSecret` rejects any
capture that is a scheme word or an existing placeholder — which makes
`redactSecretsInText` idempotent by construction. A regression test asserts it.

### Cost

Measured on the store benchmarks (`go test ./internal/store/ -bench Redact`,
16-core Linux):

| case | ns/op | allocs |
|---|---|---|
| clean string (no hint) | 177 | 0 |
| hint hit, no pattern match | 14,797 | 0 |
| bearer token in a curl (match) | 18,279 | 6 |

A hint pre-filter (`mayContainSecret`) gates the regex sweep on cheap substring
checks, keeping ordinary input — paths, short commands — at ~180 ns.

Against ADR 0002-latency-as-engineering-metric's ~10 ms typical / <50 ms target
end-to-end p95, the worst case is **~0.2% of the typical budget**. It is also
not on the agent-visible path at all: per ADR 0019 redaction runs in the
daemon's *async* write path, immediately before the `INSERT`, after the verdict
has already been returned to the hook. The latency cost to the agent is zero;
the benchmark bounds daemon write throughput, not decision latency.

### Build, not vendor

The pattern set was cross-checked against
[deja-vu](https://github.com/vshulcz/deja-vu)'s `internal/redact` (MIT), which
solves the same problem for indexed agent transcripts and independently
converged on nearly the same list. We take the **coverage checklist** as prior
art and **write our own implementation**, because:

- It is ~12 regexes. The dependency-to-value ratio does not justify a module.
- deja-vu's redactor is one file inside a transcript indexer built on choices we
  reject (a bespoke on-disk index; shelling out to the `sqlite3` binary, which
  our type-safe store rule forbids). Depending on the module drags that in.
- Our replacement semantics differ deliberately: we redact a capture group to
  preserve surrounding context, and we must not re-match our own placeholders,
  because our output is read back through `agentjail logs`/`replay`.

No new dependency, so no `make licenses` change.

## Consequences

+ A secret in a positional value — the `Bash`/`Write` case, which is most tool
  calls — is redacted. ADR 0019's "safe to browse, safe to attach to a bug
  report" claim is now true for the common path, not just the labelled one.
+ Replay stays legible: the command, URL, and flags survive; only the credential
  is replaced, tagged with its type.
+ Both `tool_input` and `audit_log.Detail` are covered by one redactor, so the
  ADR 0019 single-boundary property is preserved.
- **Recognition is prefix/shape-based, so novel or unlabelled secrets are still
  missed.** A bare high-entropy blob under a key like `arg3` matches nothing.
  Entropy-based detection was considered and rejected for now: its
  false-positive budget is unsized, and a redactor that eats random-looking
  build IDs would make replay useless. The key rule remains the backstop.
- Over-redaction is possible (`--password=…` inside a documented example
  command gets replaced). Consistent with ADR 0019: over-redaction is safe,
  under-redaction is not.
- **Existing DB rows are not retroactively scrubbed, and will not be.** Any
  secret written by a prior version stays until retention
  (ADR 0071-retention-vacuum-and-wal-checkpoint) ages it out. Accepted
  deliberately, not deferred: the DB is 0600, user-owned, and agent-unreadable,
  so an already-written secret is exposed only to the person whose secret it
  is. Rewriting history in place to fix that trades a bounded, known exposure
  for the risk of a migration that corrupts the store. Anyone who wants a clean
  DB today can delete it. No follow-up ticket exists — do not open one without
  a new reason.
