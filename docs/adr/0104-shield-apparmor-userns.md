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
more than the tunnel needs), installed to `/etc/apparmor.d/` by `agentjail
install --with-apparmor` / `agentjail doctor --fix` **only with explicit user
consent** (it needs root once). This scoped profile is the **only** mechanism
agentjail uses to enable the tunnel on a userns-restricted host.

**Validated (spike, 2026-07-20, Ubuntu 24.04.4 / AppArmor 4.0.1, restriction left
ON):** a `flags=(unconfined)` profile carrying only `userns,`, attached to
`~/.agentjail/bin/agentjail{,-shield}`, lifts the restriction for that binary
alone. Verified via both the symlink argv0 and the resolved path; plain
`/usr/bin/unshare` stayed blocked (scoped, not global). `flags=(unconfined)` does
not mediate files/caps, so it cannot conflict with the shield's Landlock /
cap-drop / no-new-privs, and no `/dev/net/tun` rule is needed. Requires AppArmor
4.x (`abi <abi/4.0>`), present on 24.04.

```
abi <abi/4.0>,
include <tunables/global>
profile agentjail-shield <install-dir>/agentjail{,-shield} flags=(unconfined) {
  userns,
  include if exists <local/agentjail-shield>
}
```

Explicitly **rejected** (supersedes the earlier 3-tier precedence):

- **The global sysctl flip** (`kernel.apparmor_restrict_unprivileged_userns=0`).
  agentjail does not suggest, document, or perform it. Weakening userns for every
  binary on the machine to enable one is the wrong trade for a security tool.
- **Silent netproxy fallback under `--tunnel`.** If the tunnel is requested and
  userns is unavailable (restricted host, no profile), agentjail does **not**
  quietly degrade to netproxy. The tunnel is either real or off, with a clear
  remediation. A tunnel that silently isn't a tunnel is the AGE-212 failure shape
  applied to network capture.

Doctor remediation on a restricted host without the profile is therefore a
**single** action: install the scoped profile (consent-gated). If declined,
network interception is OFF and doctor says so plainly — core protection
(commands, files, MCP, sandbox) is unaffected. Netproxy is never presented as a
tunnel substitute.

**Netproxy deprecation.** The transparent tunnel becomes the default
network-interception path; netproxy is deprecated and removed over the next
couple of releases. Until removed it survives only as the explicit, non-default
`--netproxy` mode (with a deprecation warning on use), never as an automatic
fallback from the tunnel.

Open questions to resolve during implementation:
- The install/consent surface: `agentjail install --with-apparmor` + a recorded
  consent marker (mirrors the path-shim consent pattern), printing the exact
  `sudo` command before running it.
- AppArmor version detection: on a <4.x host the `userns` rule won't load; the
  installer reports "tunnel unavailable on this host" rather than falling back.

## Consequences

- Ubuntu 23.10+ users get the full tunnel with **no** system-wide weakening — the
  security-correct and only path.
- Exactly one privileged step remains: loading the profile — one-time,
  consent-gated, scoped to one binary. No persistent root daemon (contrast the
  classic-VPN model).
- Deprecating netproxy collapses the datapath to a single mode; the deprecation
  window needs a warning on explicit `--netproxy` use.
- New artifact to maintain (an AppArmor profile) + a per-distro install path.
  Non-AppArmor or AppArmor <4.x hosts: the tunnel is unavailable and doctor says
  so — there is no silent fallback.
