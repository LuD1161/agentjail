# 0097 — Linux KEK fallback

Status: Accepted

## Context

[ADR 0096-linux-secret-service](./0096-linux-secret-service.md) wraps body DEKs
under a KEK held by the OS keychain. On macOS the login keychain is unlocked at
login, so this works. On Linux it frequently does not, and plan 014 §5 did not
say what happens then.

Measured on a representative Linux host:

| Mechanism | State |
|---|---|
| Secret Service | present, default collection **LOCKED** |
| `/var/lib/systemd/credential.secret` | root-only — `systemd-creds` fails as the user |
| `/dev/tpmrm0` | `crw-rw---- tss tss` — user not in `tss` |

All three doors are shut for a user-level daemon. `install.sh` is user-level
throughout (no `sudo`, installs to `$HOME/.agentjail/bin`), so `/var/lib/agentjail`
cannot be created without changing the install story. `XDG_RUNTIME_DIR` is tmpfs
and dies at logout, which is plan 014 §5's rejected option C.

Today a locked keyring means bodies are recorded in the clear.

Plan 014 §5 called "a KEK in a file" the trap. That is imprecise, and this ADR
amends it: the trap is a key stored **beside** the ciphertext. A key in a file
elsewhere is a different proposition, and the honest question is only *which
copy* it survives.

## Decision

**Linux falls back to a file KEK at `~/.config/agentjail/kek`** (0600, 32 random
bytes) when Secret Service is unreachable or locked. The ladder is: Secret
Service if unlocked, file KEK otherwise. Bodies are therefore always encrypted;
plaintext capture stops being a normal outcome.

`~/.config/agentjail` is added to `ConfigCredentialSubdirs()`
(`shield_agentpaths.go`). This is **load-bearing, not hygiene**: `~/.config` is
granted read-only to the agent so MCP server configs stay reachable, so without
the carve-out the KEK is readable by the sandboxed agent by default — handing it
the key while `doctor` reports "encrypted". Both backends translate the shared
list (ADR 0034-platform-backend-shared-contract), so one entry covers both.

macOS is unchanged: the login keychain is reached via `store_darwin.go`.

We explicitly **reject Chromium's fallback**, which encrypts under the hardcoded
password `peanuts` when no keyring is present — equal to not using a password at
all. Our fallback is a real random key; the difference is where it lives, not
whether it exists.

## Consequences

- **The tiers are not equivalent, and `doctor` must not flatten them.** A file
  KEK survives a copy of `~/.agentjail` (support bundles, issue attachments, a
  synced or backed-up agentjail dir). It does **not** survive a whole-`$HOME`
  backup, which takes key and ciphertext together. Secret Service and macOS
  Keychain do. `doctor` reports which tier is live and what it buys; claiming a
  flat "encrypted" would be a lie in the file-KEK case.
- **This still does not stop the agent.** It never did (ADR 0076 S-C1: same uid,
  so 0600 is not a boundary). Mediation of the agent's reads is ADR 0092 D3's
  job. The carve-out above is D3 doing that job, not this KEK doing it.
- **Not stolen-disk protection.** That is FDE's job.
- Rotation is unaffected: the KEK is opaque to the envelope, and `emeta` rewrap
  (ADR 0095-chunked-body-envelope) works the same under either backend.
- Losing `~/.config/agentjail/kek` makes existing bodies unreadable. This is
  correct — they are transcripts, not records of account — and D2 retention will
  reap them regardless.
- `/var/lib/agentjail` + `sudo` at install remains available later if
  whole-`$HOME`-backup resistance is wanted by default; TPM2 (via a `tss` group
  grant) remains an opt-in upgrade. Neither is taken now.
