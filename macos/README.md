# AgentJail for macOS

AgentJail ships one customer-facing macOS application. `AgentJail.app` combines
the native menu-bar experience, the transparent Network Extension, and the CLI
payload without collapsing their runtime trust boundaries. See
[ADR 0141-unified-macos-app](../docs/adr/0141-unified-macos-app.md).

## Bundle layout

```text
AgentJail.app/
└── Contents/
    ├── MacOS/
    │   └── AgentJail
    ├── Resources/
    │   ├── AgentJail.icns
    │   └── bin/
    │       ├── agentjail
    │       └── agentjail-hook
    └── Library/SystemExtensions/
        └── com.blinkerlm.agentjail.app.extension.systemextension/
            └── Contents/MacOS/
                └── com.blinkerlm.agentjail.app.extension
```

The SwiftUI executable owns setup, status, review presentation, and the fixed
Network Extension command surface. The daemon remains the policy and audit
authority. The extension performs per-process transparent network enforcement.
The bundled Go binaries remain the terminal and automation interface.

On first launch, the app checks that it is running from `/Applications`, shows
the exact local components and Apple approval that setup will request, installs
the bundled CLI/daemon/hooks with one explicit click, then activates and verifies
the Network Extension. A process-local CA is created only for protected sessions;
setup never installs a system-wide root certificate.

## Local universal build

```sh
make macos-app
make macos-dmg
```

The default produces an ad-hoc-signed, local-only universal app and DMG at:

- `build/AgentJail.app`
- `build/AgentJail.dmg`

Every executable in the bundle must contain both `arm64` and `x86_64`. The
builder injects one application version and build number into the app and
extension, signs nested code before the container, and verifies every signature
and architecture before publishing the output path. Override build metadata with
`MACOS_APP_VERSION=X.Y.Z` and `MACOS_BUILD_NUMBER=N`.
The tag workflow injects the telemetry backend and self-update signature keys via
`POSTHOG_KEY` and `SELFUPDATE_SIGNING_PUB_KEY`; local builds may omit both.
`LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES` are included under
`Contents/Resources` in every bundle.

An ad-hoc build is for local development only. It is not a distributable claim
and should not replace an activated Developer ID build on a test or customer Mac.

## Developer ID distribution build

Read [`docs/runbooks/macos-tunnel-release.md`](../docs/runbooks/macos-tunnel-release.md)
before signing, replacing, installing, or notarizing the app.

```sh
PROFILE_DIR=/absolute/path/to/profiles \
APPLE_SIGNING_IDENTITY='Developer ID Application: Aseem Shrey (Q98Z3744J2)' \
SIGNING_MODE=developer-id \
NOTARY_PROFILE=agentjail-notary \
NOTARIZE=1 \
MACOS_APP_VERSION=1.7.0 \
MACOS_BUILD_NUMBER=1171 \
make macos-app
```

The profile directory must contain:

- `com.blinkerlm.agentjail.app.provisionprofile`
- `com.blinkerlm.agentjail.app.extension.provisionprofile`

The build refuses profiles whose Team ID, application identifier,
`ProvisionsAllDevices`, or Network Extension entitlement does not match the
bundle. Notarization accepts a named keychain profile, or the explicit
`ASC_KEY`, `ASC_KEY_ID`, and `ASC_ISSUER_ID` variables. The script never sources
repository `.env` files and never prints credential values.

After the app is notarized and stapled, package and optionally notarize the DMG:

```sh
NOTARY_PROFILE=agentjail-notary NOTARIZE=1 make macos-dmg
```

Never modify, rebuild, or re-sign the app after notarization.

## Network Extension command surface

Normal users do not invoke these commands directly; `agentjail-shield --tunnel`
drives them through the installed app executable.

```sh
/Applications/AgentJail.app/Contents/MacOS/AgentJail install-extension
/Applications/AgentJail.app/Contents/MacOS/AgentJail start /path/to/wg.conf
/Applications/AgentJail.app/Contents/MacOS/AgentJail stop
```

`install-extension` submits the standard Apple activation request and saves the
transparent-proxy profile. It may display the normal approval request in System
Settings. AgentJail never automates or bypasses that decision.

The extension is inert until a tunnel session starts. Each session creates a
fresh in-memory MITM authority and process-local trust; the app does not install
a persistent root certificate and release images never contain one.

## Release gates

A public macOS artifact is ready only when all of the following pass:

1. Swift tests and Go tests for the changed packages.
2. Universal architecture and strict nested-signature verification.
3. Matching app/extension versions, bundle IDs, profiles, Team ID, and
   entitlements.
4. Apple notarization, stapling validation, and Gatekeeper result
   `source=Notarized Developer ID`.
5. Clean-machine install with explicit Network Extension approval.
6. Reboot persistence and strict tunnel smoke with executed scenarios and
   post-watermark request/audit evidence.
7. A real Intel hardware run before publishing an Intel download claim.

The stopped Tart golden remains useful for regression tests, but it is not a
substitute for the clean downloaded-customer flow.

## Source map

| Path | Responsibility |
|---|---|
| `AgentJail/` | containing-app plist and entitlements |
| `AgentjailApproval/` | SwiftUI app, daemon review client, settings, and tests |
| `AgentjailApproval/Sources/AgentjailApprovalApp/Tunnel/` | fixed extension command surface |
| `AgentjailExtension/` | `NETransparentProxyProvider` implementation and metadata |
| `scripts/build-macos-app.sh` | universal assembly, signing, verification, notarization |
| `scripts/package-macos-dmg.sh` | drag-install DMG packaging and optional notarization |
