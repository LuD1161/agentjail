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

**Chromium's precedent does not answer our case, so we answer it explicitly.**
Contributors to the r/netsec thread that popularised `peanuts` state it was
deprecated in early 2011 and kept only to migrate pre-upgrade credential DBs (an
upgraded Chromium copies them into the keystore and deletes the old DB), and
that Chromium has used the OS keystore — GNOME/KDE, Keychain, DPAPI — ever
since. So `peanuts` was never Chromium's answer to a missing keyring, and citing
it as a rejected design would be a strawman.

What that thread never answers is its own top reply: whether `peanuts` is still
what you get when the keystore is *denied or absent*. That unanswered question is
exactly our situation. Our answer is a random 32-byte key — the difference from
`peanuts` is where the key lives, not whether one exists.

## Consequences

- **The tiers are not equivalent, and `doctor` must not flatten them.** A file
  KEK survives a copy of `~/.agentjail` (support bundles, issue attachments, a
  synced or backed-up agentjail dir). It does **not** survive a whole-`$HOME`
  backup, which takes key and ciphertext together. Secret Service and macOS
  Keychain do. `doctor` reports which tier is live and what it buys; claiming a
  flat "encrypted" would be a lie in the file-KEK case.
- **The silent downgrade is the failure mode to avoid, and it is not
  hypothetical.** That same thread's OP reports gnome-keyring running,
  `--password-store=gnome` set explicitly, and cookies still unencrypted with no
  warning at all: "I would expect to see some warning if the gnome keyring is not
  going to be used." Shipping encryption that quietly does nothing is worse than
  shipping none, because it is believed. This is what AGE-254's posture
  reporting exists to prevent.
- **This still does not stop the agent.** It never did (ADR 0076 S-C1: same uid,
  so 0600 is not a boundary). The thread asks this too — how a keystore protects
  a key from another process running as the same user — and never answers it. It
  does not. Mediation of the agent's reads is ADR 0092 D3's job; the carve-out
  above is D3 doing that job, not this KEK doing it.
- **Not stolen-disk protection.** That is FDE's job.
- Rotation is unaffected: the KEK is opaque to the envelope, and `emeta` rewrap
  (ADR 0095-chunked-body-envelope) works the same under either backend.
- Losing `~/.config/agentjail/kek` makes existing bodies unreadable. This is
  correct — they are transcripts, not records of account — and D2 retention will
  reap them regardless.
- `/var/lib/agentjail` + `sudo` at install remains available later if
  whole-`$HOME`-backup resistance is wanted by default; TPM2 (via a `tss` group
  grant) remains an opt-in upgrade. Neither is taken now.
