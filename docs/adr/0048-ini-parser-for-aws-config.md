# ADR 0048: Use gopkg.in/ini.v1 to parse ~/.aws/config

**Status:** Accepted

## Context

`policyeval.ParseAWSConfig` resolves the AWS account id a `aws` CLI command
targets by reading `~/.aws/config` and looking up the `--profile`'s
`role_arn` / `sso_account_id` / `source_profile`. This drives the AWS posture
policy (`aws_posture.rego`), so a parse that silently drops or misreads a key
weakens an enforcement decision.

The original implementation was a hand-rolled line scanner: split on `\n`,
strip `#`/`;` comment lines, match `[section]` headers, and split `key = value`
on the first `=`. It worked for the common case but did not follow the INI
spec that the AWS CLI itself uses. Known gaps (Codex review + AGE-106 audit):

- **Inline comments** — `role_arn = arn:... # prod role` kept the comment in the
  value.
- **Quoted / multi-line values** — no continuation or quote-aware handling.
- **Comment-char edge cases** — `#`/`;` only recognised at the start of a
  trimmed line, not mid-line.

The account id feeds a security decision, so "close enough" parsing is a
liability, not a convenience.

## Decision

Replace the hand-rolled scanner with [`gopkg.in/ini.v1`](https://gopkg.in/ini.v1)
(v1.67.1), the de-facto Go INI library (3.4k stars, used by the AWS SDK's own
shared-config loader lineage). `ParseAWSConfig` now calls `ini.Load` and maps
sections to profiles with the AWS convention:

- `[default]` → the `default` profile.
- `[profile <name>]` → the `<name>` profile.
- ini's own `DEFAULT` root section, `[sso-session ...]`, `[services ...]`, and
  any other section are skipped.

Only `role_arn`, `sso_account_id`, and `source_profile` are read, exactly as
before. The now-unused `SplitAWSConfigKV` helper is deleted (no dead code).

The `content string` signature and `map[string]awsProfileInfo` return type are
unchanged, so every caller and the existing `ParseAWSConfig` test suite are
untouched and still pass.

## Consequences

- **Positive:** Spec-correct handling of inline comments, quoting, and comment
  characters; ~50 lines of bespoke parsing removed; behaviour now matches what
  the AWS CLI expects.
- **Positive:** One well-maintained dependency (`gopkg.in/ini.v1`, ISC-style
  Apache-2.0 licensed, ~100 KB compiled) shared across the daemon.
- **Neutral:** New direct dependency. Justified per AGE-106; attribution added
  to `THIRD_PARTY_LICENSES` via `make licenses`.
- **Trade-off:** ini.v1's section-inheritance semantics (keys in the root
  `DEFAULT` section are visible to child sections) differ from the old scanner,
  but AWS config files do not use root-level keys, and we skip the root section
  entirely, so no profile inherits stray values.
