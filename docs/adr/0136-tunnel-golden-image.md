# ADR 0136 — tunnel golden image

- **Status:** Accepted
- **Date:** 2026-08-13
- **Deciders:** agentjail-core
- **Related:** [ADR 0053-vm-testbed-engine](0053-vm-testbed-engine.md), [ADR 0077-tunnel-mitm-default-and-consent](0077-tunnel-mitm-default-and-consent.md)

## Context

Apple requires explicit user approval before a system extension can activate.
Apple's SystemExtensions documentation says the extension is packaged inside its
containing app, and the activation delegate reports when user approval is required.
A newly-created headless Tart guest cannot complete that GUI-only decision.

The Darwin tunnel smoke test previously treated an unavailable extension as a SKIP
and returned success. A release run could therefore be green while every
extension-dependent scenario was skipped. Creating every macOS testbed from the
a vanilla image made that false-success path the default.

Tart clones the complete guest disk. The approved extension state, its containing
application, and the operating system's system-extension registration therefore
survive an APFS disk clone. The MITM session authority is different: AgentJail
generates a fresh in-memory CA for each session and configures process-local trust,
so no CA should persist in a golden disk.

## Decision

Maintain one stopped Tart image, `golden-macos-mitm`, as the macOS testbed base.
It contains the approved `com.blinkerlm.agentjail.app.extension` and its exact
containing app at `/Applications/AgentjailTunnel.app`; it contains no MITM CA.
The installed extension remains inert until AgentJail starts a tunnel session,
so non-tunnel workflows may clone the same disk without enabling interception.

The image rebuilt and clone-validated on 2026-08-15 uses app version 0.0.6 build 6,
signed by Team `Q98Z3744J2`; app bundle ID
`com.blinkerlm.agentjail.app`, app CDHash
`c2dc61054cd2dfb8f06a3b6f399c805d0ca5e683`, extension bundle ID
`com.blinkerlm.agentjail.app.extension`, and extension CDHash
`b54dbeece72d5b83cfd6f4364f1b4d4998a25351`. The app is Developer ID signed,
notarized, stapled, and accepted by Gatekeeper. Its embedded Developer ID
profiles have `ProvisionsAllDevices=true`, so the Tart hardware identifier does not
need Apple Developer device registration. The signed app and extension entitlement
is `app-proxy-provider-systemextension` and the app carries the system-extension
install entitlement.

All Tart workflows select `golden-macos-mitm`. A strict tunnel smoke run distinguishes an
activated extension, a missing or inactive extension, executed scenarios, and
skipped scenarios. Strict mode fails when the extension is unavailable or when no
tunnel scenario executes. The real-agent tunnel scenario likewise fails, rather
than skips, when the containing app or activated extension is absent.

Launches that claim tunnel coverage use `--require-tunnel`. It implies
`--tunnel` but changes setup failure from the normal fallback behavior to a
non-zero exit. PATH-shim compatibility scenarios opt into the same contract
with `AGENTJAIL_REQUIRE_TUNNEL=1`. Tests watermark `audit_log` and require a
successful `tunnel.session_registered` event with no post-watermark
`tunnel.extension_started` failure reason; stdout and stderr remain diagnostic.

The contract is validated by cloning the stopped golden, booting the clone
headlessly, checking `systemextensionsctl list` for `[activated enabled]`, and
running strict smoke with at least one executed tunnel scenario. Apple
[System Extensions](https://developer.apple.com/documentation/systemextensions)
and
[`requestNeedsUserApproval(_:)`](https://developer.apple.com/documentation/systemextensions/ossystemextensionrequestdelegate/requestneedsuserapproval%28_%3A%29)
were checked on 2026-08-13; the disk-clone persistence behavior was verified live
with Tart on the same date.

## Consequences

- The one-time approval is a deliberate guest preparation step and is never
  bypassed, scripted, or weakened. Fresh headless guests cannot substitute for it.
- A single stopped golden avoids retaining a second 20–25 GB vanilla disk while
  keeping non-tunnel workflows unaffected until they explicitly start a tunnel.
- Rebuild the image when the app or extension version, CDHash, Team ID, bundle ID,
  provisioning profiles, or entitlements change; when an OS update invalidates the
  activation.
- The baked artifact's signature, notarization ticket, and Gatekeeper acceptance
  are verified. Disk-clone validation still does not prove a clean downloaded
  customer installation or production distribution readiness.
- A required tunnel release assertion can no longer pass by reporting only SKIPs.
- A required real-agent assertion cannot launch through a fallback path and
  cannot infer tunnel state from terminal text.
