# 0096 — Linux Secret Service

Status: Accepted

## Context

Plan 014 §5 picks a keychain-held KEK to wrap the per-file DEKs that encrypt
captured bodies. macOS has a backend (`security(1)`). Linux returned
`ErrNoKeychain` unconditionally — a named exception under
[ADR 0034](./0034-platform-backend-shared-contract.md), not a decision. Linux is
also the only platform with a working tunnel, so it is the only platform that
currently has bodies to encrypt. The gap was the whole feature.

Two Linux primitives were candidates:

- **Kernel keyring** — already rejected by plan 014 §5. Persistent keys expire
  by default, which breaks D2's 90-day readable retention for the same reason
  §5 rejects option C (daemon-memory-only key). Not revisited here.
- **Secret Service D-Bus API** (`org.freedesktop.secrets`, implemented by
  gnome-keyring and kwallet) — persistent, and the same primitive Chrome and
  every other Linux desktop app uses. Chosen.

### The dependency is a promotion, not an addition

`github.com/godbus/dbus/v5 v5.1.0` was already in `go.mod` as `// indirect`,
already compiled into the binary (`internal/notify` → `gen2brain/beeep` →
`godbus/dbus/v5`), and already attributed at `THIRD_PARTY_LICENSES:35`. This ADR
records promoting it to a **direct** dependency. No new module enters the build;
`go.sum` is unchanged by the promotion.

That is a real but bounded change, and it should not be sold as free: an
indirect dependency is one our dependency maintains against, while a direct one
is one **we** now maintain against. We own its upgrades and its CVEs from here.
The supply-chain surface is unchanged; the maintenance surface grew.

Writing the Secret Service protocol against godbus directly, rather than adding
a wrapper library (`zalando/go-keyring`, `99designs/keyring`), keeps that
surface at exactly one module.

## Decision

**Implement the Secret Service API in `store_linux.go` behind the existing
`Store` seam.** The contract in `keyring.go` is unchanged: the backend is a dumb
`Get`/`Set`/`Name` item store, and KEK naming, sizing, fingerprinting, and the
wrap format stay in the one tag-free file for every platform (ADR 0034).

Four decisions the protocol forces, none of which the contract should know:

1. **The persistent default collection only, resolved via
   `ReadAlias("default")`.** gnome-keyring also exposes an ephemeral `session`
   collection that is always unlocked and dies at logout. It would satisfy a
   naive backend and every functional test, and would silently deliver plan 014
   §5's *rejected* option C — a process-lifetime key — arrived at by accident.
   Bodies would outlive their KEK and become permanently unreadable. Reads are
   scoped to the resolved collection (`Collection.SearchItems`) rather than
   `Service.SearchItems`, which would sweep the ephemeral collection too.

2. **Never drive a prompt.** If the default collection is locked, `Unlock` is
   attempted once; if the daemon answers with a prompt object, it is dismissed
   and `Open()` returns `ErrNoKeychain`. A background recorder cannot answer a
   password dialog, and plan 014 §5 requires a prompt/hang deadline. This is not
   hypothetical: on a headless-but-logged-in host, `secret-tool store` hangs
   forever on exactly this path.

3. **Every call is bounded, and so is the dial.** `dbusDeadline` (3s) bounds each
   D-Bus call. `Auth` and `Hello` take no context, so the whole dial runs under a
   `select` timeout and a late-arriving connection is closed rather than leaked.
   A recorder must never stall a captured request on a bus that is absent,
   wedged, or waiting on a human.

4. **Discover a bus, never spawn one.** `SessionBusPrivateNoAutoStartup` — the
   autolaunch path shells out to `dbus-launch` and starts a daemon. A private
   connection, not the shared `SessionBus()`, so this package's lifecycle cannot
   disturb `internal/notify`'s.

**The absent case stays typed and prompt.** No bus, no default collection,
locked-with-a-prompt, or a bus that refuses us all return `ErrNoKeychain`
quickly. Whether that fails recording closed or degrades to plaintext with a
loud notice remains plan 014 §9.2's decision at one call site — not this
package's.

**`plain` transfer, not the DH handshake.** The bus is a same-uid `AF_UNIX`
socket and same-uid is explicitly not this package's threat model, so the
handshake would buy nothing real.

## Consequences

- Linux gets a real KEK, so bodies can be encrypted at rest on the one platform
  that has a tunnel. Plan 014 §5 option A is now implemented on both platforms.
- `godbus/dbus/v5` is ours to maintain: its upgrades and CVEs are now a direct
  obligation, where before `beeep` absorbed them.
- **A locked keyring reads as "no keychain."** A headless-but-logged-in host —
  a server, a CI box, a container, this development host — hits this. It is
  correct (we will not hang) but it means the common server case degrades per
  §9.2 rather than encrypting. Unlocking at login (PAM) is the operator's lever.
- **What this buys is narrow, and stated narrowly.** The sandboxed agent runs as
  the same uid; Secret Service hands the secret to any process running as the
  user. This does not stop the agent, exactly as Chrome's cookie encryption does
  not stop same-uid infostealers. It buys that a body transcript survives an
  accidental *copy* — a backup, a sync client, a support bundle — without its
  key. Stolen-disk protection is FDE's job; mediating the agent's reads is
  [ADR 0092](./0092-persist-request-bodies.md) D3's.
- A restored `bodies/` without the KEK is unreadable. That is the feature
  working; plan 014 §5 requires it be documented, not discovered.
- kwallet implements the same API and should work unmodified, but is untested.
- The real-Secret-Service tests are opt-in (`AGENTJAIL_KEYRING_E2E=1`): they
  write to the caller's actual keychain, and CI has no bus.
