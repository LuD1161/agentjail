# ADR 0135 — tunnel golden image

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
vanilla `golden-macos` image made that false-success path the default.

Tart clones the complete guest disk. The approved extension state, its containing
application, and the operating system's system-extension registration therefore
survive an APFS disk clone. The MITM session authority is different: AgentJail
generates a fresh in-memory CA for each session and configures process-local trust,
so no CA should persist in a golden disk.

## Decision

Maintain two separate stopped Tart images:

- `golden-macos` remains the general-purpose vanilla testbed base.
- `golden-macos-mitm` is the explicit macOS tunnel base. It contains the approved
  `com.blinkerlm.agentjail.app.extension` and its exact containing app at
  `/Applications/AgentjailTunnel.app`; it contains no MITM CA.

The image baked on 2026-08-13 is test-only. Its app is version 0.0.2 build 2,
signed by Team `Q98Z3744J2`; app bundle ID
`com.blinkerlm.agentjail.app`, app CDHash
`a85f751c07e5e99a8a8164fd1ac8d9e4fff8d05e`, extension bundle ID
`com.blinkerlm.agentjail.app.extension`, and extension CDHash
`9b067cad054dd49bf68a910aca64c14f70462fa7`. Its embedded Developer ID
profiles have `ProvisionsAllDevices=true`, so the Tart hardware identifier does not
need Apple Developer device registration. The signed app and extension entitlement
is `app-proxy-provider-systemextension` and the app carries the system-extension
install entitlement.

Tunnel release assertions on Tart select `golden-macos-mitm`; unrelated macOS
workflows continue to use `golden-macos`. A strict tunnel smoke run distinguishes an
activated extension, a missing or inactive extension, executed scenarios, and
skipped scenarios. Strict mode fails when the extension is unavailable or when no
tunnel scenario executes. The real-agent tunnel scenario likewise fails, rather
than skips, when the containing app or activated extension is absent.

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
- Rebuild the image when the app or extension version, CDHash, Team ID, bundle ID,
  provisioning profiles, or entitlements change; when an OS update invalidates the
  activation; or when the final production Developer ID/notarized artifact becomes
  available.
- This test-only image proves the tunnel and MITM path. It does not prove
  Gatekeeper behavior for a downloaded release, notarization, stapling, clean
  customer installation, or production distribution readiness.
- A required tunnel release assertion can no longer pass by reporting only SKIPs.
