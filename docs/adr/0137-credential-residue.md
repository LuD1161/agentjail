# ADR 0137 — credential residue

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** agentjail-core
- **Related:** [ADR 0032-credential-broker-tier15](0032-credential-broker-tier15.md), [ADR 0084-redact-secret-values](0084-redact-secret-values.md)

## Context

Credential values are encrypted in the broker vault and excluded from structured
audit details. A raw evidence review nevertheless found disposable AWS fixture
values in free bytes of `agentjail.db` after no logical SQLite row contained
them. Logical queries alone therefore could not prove that secret-bearing values
were absent from retained storage.

Decision summaries were a second serialization path. Full tool input was
redacted, but a human-readable command summary could reach logs and the decision
store without the same value-level redactor. SQLite also used its default delete
behavior, which may leave deleted cell contents in free pages.

## Decision

Apply the shared value-level redactor to decision summaries before logging and
again at the store boundary. Open the writable AgentJail SQLite singleton with
`secure_delete=ON` so deleted cells are overwritten rather than retained as
free-page bytes.

Credential storage tests exercise the real encrypted vault, broker request,
audit, and removal lifecycle, then scan the database, WAL, and shared-memory
files as bytes. Release evidence scans use the actual disposable authentication
values and require a temporary positive control before reporting that retained
artifacts are clean. Evidence manifests bind a clean gate to its pre-install
state, exact installer inputs, source tree, scenarios, results, and raw guest
archive.

## Consequences

- A structured row that appears redacted is no longer sufficient credential
  hygiene evidence; the backing files are scanned after deletion and close.
- Human-readable summaries remain useful, but secret-shaped values are replaced
  by the same deterministic redaction used for tool input.
- `secure_delete=ON` adds bounded write work when SQLite removes data. This is
  outside the policy decision hot path and is accepted for defense in depth.
- Raw evidence mode is explicit, owner-only, and temporary. Its archive is not
  sanitized, must never be committed, and is deleted only after independent
  review.
