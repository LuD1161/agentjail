# ADR 0141-unified-macos-app: Unified macOS app

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** agentjail-core
- **Related:** AGE-293, [ADR 0133-macos-menu-review](0133-macos-menu-review.md), [ADR 0136-tunnel-golden-image](0136-tunnel-golden-image.md)
- **Supersedes:** the final distribution decision in [ADR 0005-macos-gatekeeper-distribution](0005-macos-gatekeeper-distribution.md) and the separate-application boundary in [ADR 0133-macos-menu-review](0133-macos-menu-review.md)

## Context

AgentJail's shipped Linux experience is CLI-first. On macOS, the implementation
grew two customer-facing applications: `AgentjailTunnel.app` contained the
Network Extension, while `AgentjailApproval.app` provided the menu-bar review
experience. The CLI release installed neither application. A customer therefore
could not obtain the complete macOS product from one download or from the normal
terminal installer.

The split was useful while the approval UI had no release-signing path, but it is
the wrong product boundary. macOS users need one recognizable application for
onboarding, permissions, health, and reviews, while terminal users still need the
same CLI available for automation. Apple requires the Network Extension to remain
a separately signed nested system extension and requires an explicit user approval
before activation. Those security boundaries do not require separate top-level
applications.

The existing individual Apple Developer membership has working Developer ID
profiles for `com.blinkerlm.agentjail` and
`com.blinkerlm.agentjail.extension`. Both profiles provision all devices. A
clean-machine test proved that a Developer ID signed, notarized, and stapled build
can be installed outside the Mac App Store and activated after the normal macOS
approval flow.

## Decision

Ship one customer-facing `/Applications/AgentJail.app` on macOS. The bundle owns
the provisioned containing-app identifier `com.blinkerlm.agentjail` and contains:

- the SwiftUI menu-bar, setup, status, and review application;
- `Contents/Library/SystemExtensions/com.blinkerlm.agentjail.extension.systemextension`;
- universal `agentjail` and `agentjail-hook` payloads under
  `Contents/Resources/bin/`.

The distribution boundary does not collapse runtime authority. The UI remains a
typed client, the daemon remains the policy and audit authority, the Network
Extension remains the transparent network-enforcement process, and the CLI remains
the terminal and automation surface. The application never reads the SQLite store
or edits policy files directly. Fixed application actions may execute the bundled
CLI without a shell; arbitrary command execution is not an application API.

The containing application is a normal foreground macOS app, not an
`LSUIElement`-only accessory. Its single primary window has exactly three tabs:
Overview, MCP, and Settings; the menu-bar review surface remains a supplemental
entry point. Overview keeps onboarding in a compact status card and obtains a
bounded, versioned, read-only dashboard projection over the authenticated daemon
control socket. The daemon supplies active and recent sessions, audited-call
aggregates, daily activity, and supported local transcript token totals. It
projects project basenames rather than full paths and never returns commands,
tool input, traffic, or credentials.

Both macOS installation routes consume the same signed artifact. The website DMG
and `curl | sh` installer verify and install the same Developer ID signed,
notarized, and stapled application, expose the bundled CLI in the user's executable
path, start the supervised daemon, and launch the same onboarding flow. Linux
remains CLI-first and does not install a desktop application.

Release signing is inside-out: CLI payloads and the system extension are signed
before the containing application. The app and extension embed their matching
Developer ID provisioning profiles. App and extension versions advance together.
The final application is notarized once, stapled, assessed by Gatekeeper, and never
mutated afterward. An Intel download is advertised only after the app, CLI, and
extension have been built and exercised on Intel hardware.

Network Extension activation remains an explicit Apple-controlled user decision.
The application explains the effect before requesting activation and never
automates or bypasses System Settings. AgentJail continues to create a fresh
session CA and apply process-local trust; no persistent MITM CA is installed by the
application or baked into a release image.

Product telemetry follows the existing typed, documented telemetry boundary.
Application onboarding and health signals may record only fixed event and outcome
enums, platform, architecture, and version. They never include paths, hosts,
commands, request data, policy contents, credentials, or extension logs. Local
security/audit evidence remains distinct from anonymous product telemetry.

## Consequences

- macOS has one product name, application bundle, DMG, onboarding flow, and
  release artifact while retaining separate least-authority processes.
- The app remains reachable through Dock and Cmd-Tab while Apple-owned System
  Settings is handling Network Extension approval.
- Dashboard token coverage is explicit: local Claude Code, Codex, and OpenCode
  transcript readers are supported; Cursor usage is not inferred.
- The approval Swift package becomes the containing application rather than a
  standalone companion; its daemon-controlled review model remains unchanged.
- The old `AgentjailTunnel.app` and approval-only DMG are migration inputs, not
  public products. Release docs, scripts, tests, and golden images must converge on
  `AgentJail.app`.
- Prototype builds used the unprovisioned `.app` bundle-ID segment. The first
  private release moves to the Developer ID profile identities and therefore
  requires one fresh, explicit Network Extension approval on upgraded test Macs.
- Public macOS distribution requires Developer ID signing, matching restricted
  entitlement profiles, notarization, stapling, and clean-machine verification.
  Ad-hoc builds remain explicitly local-only.
- Customers do not need a Mac App Store build or an Apple Organization account,
  but they must approve the Network Extension once when macOS requests it.
- Product funnel metrics become useful for identifying setup failures without
  expanding the sensitive network or policy data that leaves the machine.
