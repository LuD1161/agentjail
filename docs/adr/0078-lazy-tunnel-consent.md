# ADR 0078: Nothing privileged at install — the first tunneled session asks

**Status:** Accepted

## Context

The tunnel costs something on some platforms: macOS needs root to open a kernel
`utun` (AGE-172), and any TLS interception needs a CA the agent trusts. The
question is *when* the user pays that cost.

The tempting answer is install time — provision a LaunchDaemon, trust a cert,
get it over with. AGE-172's plan says exactly that: "LaunchDaemon install for
one-time privilege (avoid per-run sudo)". That is the wrong shape:

- It charges **every** user for a feature **some** will never turn on. A user who
  installs agentjail for the hook/filesystem sandbox and never runs `--tunnel`
  has no reason to be asked for an admin password.
- An install that asks for sudo is a materially harder install. `curl | sh`
  asking for a password is where people stop.
- It front-loads a consent decision at the moment the user has the least context
  for it. "Allow network tunnelling?" means nothing during install; it means
  something concrete when you are starting a tunneled session.

Today's Linux path already has the right shape, by construction (ADR 0079): the
tunnel uses unprivileged user+net+mnt namespaces, so it needs **no sudo ever**,
and the interception CA is bind-mounted over the trust store **inside the agent's
mount namespace** (`netns.InjectCA`) with its private key in memory only
(`mitm.GenerateCAInMemory`). The host trust store is never modified. `install.go`
provisions nothing tunnel-related. So on Linux there is nothing to ask for.

macOS is where this bites, and macOS is where the install-time plan exists.

## Decision

**Installation never asks for privilege or modifies trust. Whatever a tunneled
session costs is paid at the first tunneled session, not before.**

### D1 — Install provisions nothing

`agentjail install` must not request sudo, install a LaunchDaemon, create a
utun, or touch any trust store. A user who never tunnels is never asked.
This is the status quo and is now a constraint, not an accident.

### D2 — The first tunneled session pays

The first time a user starts a session with the tunnel on, that session performs
whatever setup the platform requires and asks for whatever it needs — at that
moment, in that context. Not earlier.

### D3 — Consent, once granted, is remembered

Grant is recorded so subsequent tunneled sessions do not re-prompt, following the
existing `telemetry.LoadConsent`/`SaveConsent` shape rather than inventing a
second consent mechanism. Revocable.

### D4 — No TTY means no prompt means no tunnel

In a non-interactive context (CI, a nested agent, no TTY), a consent prompt
cannot be answered. Such a session must fall back to netproxy with a clear
message — never hang waiting on stdin, and never silently self-grant. Fail-open
to netproxy is the floor (ADR 0079).

### D5 — Per-platform cost, one shape

The *when* is shared contract (ADR 0034); only the cost differs:

| Platform | Cost at first tunneled session |
|---|---|
| Linux | **nothing** — unprivileged userns, netns-scoped CA, no sudo. No prompt needed |
| macOS CLI (AGE-172) | admin password for the kernel utun; provision then, not at install |
| macOS app (AGE-67) | the OS system-extension approval dialog |

Linux needing no prompt is not an exception to this ADR — it is this ADR's
target state, reached for free.

## Consequences

- **AGE-172 changes shape.** Its "LaunchDaemon install for one-time privilege"
  task moves out of install and into first-tunneled-start. That ticket must be
  updated; this ADR is the reason.
- **`curl | sh` stays password-free.** The install story remains "no sudo",
  which is also what ADR 0005's unsigned/Gatekeeper strategy depends on.
- **macOS pays per-provision, not per-run.** Deferring to first use does not mean
  sudo on every run: the first tunneled session provisions the LaunchDaemon, and
  later sessions reuse it (D3).
- **Nothing to build on Linux today.** The requirement is already met by ADR
  0079's zero-privilege design. This ADR exists to keep it that way and to
  constrain the macOS work before it lands the wrong way.
- **Tunnelling stays per-session opt-in for now** (`--tunnel`). Making it
  default-on (AGE-171) is a separate decision; when it happens, D1/D2/D4 still
  hold — a default-on tunnel on Linux costs nothing and prompts nothing, while
  on macOS a default-on tunnel would still have to ask at first use.

## Related

- [ADR 0079](./0079-agent-netns-veth-vs-userns-tunfd.md) — unprivileged userns;
  why Linux costs nothing.
- [ADR 0077](./0077-tunnel-mitm-default-and-consent.md) — the posture *inside* a
  tunneled session (interception on by default, announced, overridable). This
  ADR governs whether the session is tunneled at all.
- [ADR 0034](./0034-platform-backend-shared-contract.md) — per-OS backends share
  the contract; the *when* is shared, the cost is not.
- [ADR 0005](../adr/) — unsigned `curl | sh` distribution, which a sudo-ful
  install would undercut.
- AGE-171 (Linux tunnel rollout), AGE-172 (macOS sudo utun — must move the
  LaunchDaemon out of install), AGE-67 (Mac app NE approval), AGE-173 (consent UX).
