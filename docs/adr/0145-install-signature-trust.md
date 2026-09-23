# ADR 0145 — Authenticate initial release downloads

Status: Accepted
Date: 2026-09-22
Supersedes: the initial-install TOFU decision in ADR 0015-auto-update-trust-model

## Context

The shell installer accepted release archives after comparing them with a
checksum downloaded from the same release endpoint. ADR 0015 accepted this
TOFU trade-off to avoid a verifier prerequisite. The Go updater already requires
a signed manifest; initial installation should authenticate that same manifest
before any release binary is extracted or executed.

## Decision

Remote `install.sh` runs require an independently installed `minisign` command
and embed the release public key also used by release.yml and the Go updater.
The installer fetches `SHA256SUMS.minisig`, verifies `SHA256SUMS`, checks the
selected archive against that authenticated manifest, and only then extracts
and installs. A missing verifier, signature, invalid signature, or checksum
mismatch is fatal. The script never downloads a verifier from the release it
is trying to authenticate and offers no unsigned remote fallback.

Users obtain minisign through a separately trusted package manager. The initial
script remains a trust anchor: a mutable script plus a mutable embedded key does
not defend against compromise of the script's own distribution. Users needing
a stronger bootstrap pin or independently review that script.

`LOCAL_TARBALL` remains an explicit development-only input for locally built
clean-VM test artifacts. It emits an unsigned-local warning and does not claim
release authentication. CI tests the remote signature path separately with
throwaway signing keys and a test-only script copy; production has no key
replacement environment variable.

Release publication requires signing credentials and a verified manifest
signature. An absent signing key or failed verification stops the release job;
missing release assets are publication failures rather than warnings through
`fail_on_unmatched_files: true`. This input was verified on 2026-09-22 against
the pinned action's [official v2 action contract](https://raw.githubusercontent.com/softprops/action-gh-release/v2/action.yml).
Publication itself is not exercised by local tests.

The minisign command contract was checked on 2026-09-22 with installed minisign
0.12, the [official usage reference](https://jedisct1.github.io/minisign/), and
live fixture signing/verification using `-V -m FILE -x SIGNATURE -P KEY -q`.
The dedicated `installer.yml` CI job installs minisign and fish independently,
checks both prerequisites, and runs those real cryptographic checks on macOS
and Linux. A fixture executes the release signing step without credentials and
requires refusal before publication.

## Consequences

- Initial remote installs now require a small external prerequisite. Existing
  one-line instructions disclose it before download; local-development gates
  keep their deliberate unsigned-artifact workflow.
- Signed historical releases remain installable; unsigned historical releases
  fail closed. The signature authenticates bytes, not freshness or rollback
  resistance; version selection is unchanged.
- Release key rotation must update the installer and release/updater key
  together. A fixture test checks that their checked-in keys match.
- No Go dependencies or downloaded bootstrap binaries are introduced.
