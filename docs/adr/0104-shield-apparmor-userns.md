# 0104 — Full tunnel on Ubuntu 23.10+ via an AppArmor userns profile

Status: Proposed (tracked in AGE-258)

## Context

The transparent tunnel needs an *unprivileged* user namespace (ADR 0079). Ubuntu
23.10+ (incl. 24.04) ships `kernel.apparmor_restrict_unprivileged_userns=1`,
which blocks unprivileged userns unless a process is covered by an AppArmor
profile that grants the `userns` capability. On such hosts the tunnel fails open
to netproxy (ADR 0103), and `agentjail doctor` currently tells the user to relax
the restriction **globally**:

```
kernel.apparmor_restrict_unprivileged_userns=0
```

That works, but it re-enables unprivileged userns for *every* binary on the
machine — a broader security relaxation than agentjail needs, and one a
security-conscious user is right to refuse. It also needs root, which agentjail's
install deliberately never takes.

Ubuntu's intended mechanism is the opposite of a global flip: keep the
restriction on, and ship a **per-binary AppArmor profile** that allows userns for
exactly the binary that needs it (this is how Chrome, and Ubuntu's own
`unprivileged_userns` profiles, coexist with the restriction).

## Decision (proposed)

Ship an AppArmor profile for `agentjail-shield` that grants `userns` (and nothing
more than the tunnel needs), installed to `/etc/apparmor.d/` by `install.sh` /
`agentjail doctor --fix` **only with explicit user consent** (it needs root).
Precedence of remediations `doctor` offers on a restricted host:

1. **Preferred:** install the scoped AppArmor profile (grants userns to
   agentjail-shield alone; the global restriction stays on for everything else).
2. **Fallback:** the global sysctl flip (ADR 0103) for users who cannot or do not
   want to load an AppArmor profile.
3. **Do nothing:** stay on netproxy (host/SNI policy still applies).

Open questions to resolve during implementation:
- The exact profile contents — the minimal rule set that lets the shield create
  the userns + TUN and re-exec itself, without turning the profile into a broad
  allow. The installed binary is a symlink to the multicall `agentjail`; the
  profile must attach to the path the kernel sees.
- Interaction with the shield's own hardening (cap-drop, no-new-privs) and the
  Landlock ruleset — the profile must not conflict.
- Whether the profile ships in the tarball and is loaded lazily on first
  `--tunnel`, or at install with consent.

## Consequences

- Ubuntu 23.10+ users get the full tunnel without weakening system-wide userns —
  the security-correct default.
- New artifact to maintain (an AppArmor profile) and a per-distro install path;
  non-AppArmor hosts ignore it.
- Until this lands, the documented remediation stays the global sysctl (ADR 0103)
  plus the netproxy fallback.
