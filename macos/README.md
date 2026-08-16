# AgentJail macOS Transparent Tunnel

This directory contains the macOS Network Extension that captures all agent
network traffic at the OS packet level — no proxy env-vars, no per-process
configuration needed.

## Architecture

```
Agent process
    |
    v (TCP/UDP flows selected by process ancestry)
NETransparentProxyProvider  (AgentjailExtension — system extension process)
    |
    |  per-flow bridge into the userspace WireGuard + gVisor netstack
    v
libagentjail_tunnel.a   (Go static library — linked into the extension binary)
    |
    v (policy-checked, optionally TLS-inspected)
upstream network
```

The provider uses the flow audit token to match descendants of the shield PID.
Matched traffic enters the per-session userspace WireGuard/netstack path;
unrelated host traffic is passed through and cannot loop back into the tunnel.

The host app (`AgentjailTunnel.app`) calls `NETunnelProviderManager` APIs to
install and start the extension.  `agentjail-shield` can drive the same
activate/deactivate flow via the CLI shim compiled from `AgentjailTunnel/main.swift`.

## Prerequisites

- macOS 12 Monterey or later
- Xcode 14+ **or** the Command Line Tools with `swiftc`
- An Apple Developer account enrolled in the Developer ID programme
- Team ID: `Q98Z3744J2` (already baked into the entitlement `$(TeamIdentifierPrefix)`)
- A provisioning profile that grants:
  - `com.apple.developer.networking.networkextension` →
    `app-proxy-provider-systemextension`
  - `com.apple.developer.system-extension.install`

## Step 1 — Build the Go static library

```sh
# From the repo root
make tunnel-lib
# Produces:
#   build/libagentjail_tunnel.a
#   build/libagentjail_tunnel.h
```

If the Makefile target does not yet exist, build manually:

```sh
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -buildmode=c-archive \
    -o build/libagentjail_tunnel.a ./internal/tunnel/cbridge/
```

For a universal (arm64 + x86_64) library:

```sh
# Build each arch
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64  go build -buildmode=c-archive -o /tmp/lib_arm64.a ./internal/tunnel/cbridge/
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64  go build -buildmode=c-archive -o /tmp/lib_amd64.a ./internal/tunnel/cbridge/
lipo -create /tmp/lib_arm64.a /tmp/lib_amd64.a -output build/libagentjail_tunnel.a
cp /tmp/lib_arm64.h build/libagentjail_tunnel.h   # header is arch-independent
```

## Step 2 — Build the Swift extension

### Using swiftc directly (quick iteration)

```sh
TEAM_ID=Q98Z3744J2
BUILD=build/AgentjailExtension

mkdir -p $BUILD

swiftc \
    -target arm64-apple-macos13.0 \
    -module-name AgentjailExtension \
    -import-objc-header macos/AgentjailExtension/BridgingHeader.h \
    -I build/ -L build/ -lagentjail_tunnel -lbsm \
    -framework NetworkExtension \
    -framework Foundation \
    -o $BUILD/com.blinkerlm.agentjail.app.extension \
    macos/AgentjailExtension/main.swift macos/AgentjailExtension/Provider.swift
```

### Using xcodebuild (recommended for distribution)

Create an Xcode project (or use the provided one when available):

```sh
xcodebuild \
    -scheme AgentjailExtension \
    -configuration Release \
    -derivedDataPath build/xcode \
    CODE_SIGN_IDENTITY="Developer ID Application" \
    DEVELOPMENT_TEAM=$TEAM_ID \
    build
```

## Step 3 — Build the host app

```sh
swiftc \
    -target arm64-apple-macos13.0 \
    -framework AppKit \
    -framework NetworkExtension \
    -framework SystemExtensions \
    -framework Foundation \
    -o build/AgentjailTunnel \
    macos/AgentjailTunnel/main.swift
```

The shield passes a per-launch generation with `start <wg-conf> <generation>`.
The extension reports that generation ready only after its WireGuard handshake
and accepts PID registration only for the same ready generation. This is an
enforcement contract: a reachable session socket alone does not prove the new
provider configuration is active.

## Step 4 — Assemble the app bundle

The canonical build and assembly path is `make macos-app` (or
`NOTARIZE=1 make macos-app` for distribution). The commands below describe its
bundle layout; keep `scripts/build-macos-app.sh` authoritative.

Read [`docs/runbooks/macos-tunnel-release.md`](../docs/runbooks/macos-tunnel-release.md)
before replacing an installed extension. It records the complete signing,
notarization, upgrade, approval, and golden-image procedure, including the
App Store Connect API-key recovery path for notary-service authentication
failures.

The system extension must be embedded inside the host app at:

```
AgentjailTunnel.app/
└── Contents/
    ├── Info.plist
    ├── MacOS/
    │   └── AgentjailTunnel
    └── Library/
        └── SystemExtensions/
            └── com.blinkerlm.agentjail.app.extension.systemextension/
                └── Contents/
                    ├── Info.plist
                    └── MacOS/
                        └── com.blinkerlm.agentjail.app.extension
```

```sh
APP=build/AgentjailTunnel.app
EXT=$APP/Contents/Library/SystemExtensions/com.blinkerlm.agentjail.app.extension.systemextension

mkdir -p $APP/Contents/MacOS
mkdir -p $EXT/Contents/MacOS

cp macos/AgentjailTunnel/Info.plist $APP/Contents/
cp build/AgentjailTunnel             $APP/Contents/MacOS/

cp macos/AgentjailExtension/Info.plist $EXT/Contents/
cp build/AgentjailExtension/com.blinkerlm.agentjail.app.extension \
   $EXT/Contents/MacOS/
```

## Step 5 — Sign

Both the extension and the host app must be signed with the same Developer ID
and the matching provisioning profiles.

```sh
TEAM_ID=Q98Z3744J2
IDENTITY="Developer ID Application: Aseem Shrey ($TEAM_ID)"

# Sign the extension first (inner-to-outer rule).
codesign --force --timestamp \
    --entitlements macos/AgentjailExtension/AgentjailExtension.entitlements \
    --sign "$IDENTITY" \
    --options runtime \
    $EXT

# Sign the host app.
codesign --force --timestamp \
    --entitlements macos/AgentjailTunnel/AgentjailTunnel.entitlements \
    --sign "$IDENTITY" \
    --options runtime \
    $APP
```

Verify:

```sh
codesign --verify --deep --strict $APP
spctl -a -vvv -t exec $APP
# For the final notarized distribution build:
xcrun stapler validate build/AgentjailTunnel.app
xcrun stapler validate build/AgentjailTunnel.dmg
```

## Step 6 — Install the system extension

Keep the containing app installed at its stable path and request activation:

```sh
/Applications/AgentjailTunnel.app/Contents/MacOS/AgentjailTunnel install
systemextensionsctl list
# Required state:
# com.blinkerlm.agentjail.app.extension ... [activated enabled]
```

If macOS requests approval, use **System Settings → General → Login Items &
Extensions → Network Extensions**. Do not bypass or automate that decision.
Apple can keep the activation pending until the user grants or denies it.

## Step 7 — Start / stop the tunnel

```sh
# Start from an AgentJail-generated per-session WireGuard configuration.
/Applications/AgentjailTunnel.app/Contents/MacOS/AgentjailTunnel start /path/to/wg.conf

# Stop the transparent proxy.
/Applications/AgentjailTunnel.app/Contents/MacOS/AgentjailTunnel stop
```

`agentjail-shield --tunnel` owns these calls in normal use. It creates a fresh
in-memory MITM CA per session, applies process-local trust, and removes the
session material during cleanup. The shield accepts the tunnel as active only
after the extension acknowledges its process registration; a missing or invalid
acknowledgement falls back without launching the agent under the broad tunnel
profile. Darwin tunnel sessions are serialized because the Network Extension
manager and WireGuard provider state are machine-global, not per workspace.
Darwin provisions IPv4 and IPv6 tunnel addresses by default. This is required
for IPv6-first destinations: Network Extension may receive an already-resolved
IPv6 endpoint even when the same hostname also has an A record. Set
`network.tunnel_ipv6: false` or pass `--no-tunnel-ipv6` only as an explicit
IPv4-only diagnostic opt-out.

## Tart tunnel golden

macOS tunnel release testing must clone the stopped `golden-macos-mitm` image.
That image contains the approved extension and the exact containing app at
`/Applications/AgentjailTunnel.app`; it contains no MITM CA. A fresh headless
guest cannot perform Apple's GUI approval, while a Tart disk clone preserves the
guest's approved system-extension state.

The image rebuilt and clone-validated on 2026-08-15 contains app version 0.0.6 build 6,
Team `Q98Z3744J2`, app CDHash
`c2dc61054cd2dfb8f06a3b6f399c805d0ca5e683`, and extension CDHash
`b54dbeece72d5b83cfd6f4364f1b4d4998a25351`. The app is Developer ID signed,
notarized, stapled, and accepted by Gatekeeper. Both embedded Developer ID
profiles use `ProvisionsAllDevices=true`, so Tart device registration is not
required. Rebuild the image for any identity, version, profile, entitlement, or
fingerprint change and when the final production artifact is available.

The baked artifact's signature, notarization, stapled ticket, and Gatekeeper
acceptance are verified. The disk-clone workflow is not evidence of a clean
downloaded-customer install or distribution readiness. See
`test/testbed/README.md` and ADR 0136-tunnel-golden-image for the validation
contract; strict smoke must execute a scenario and must never report all-SKIP as
success.

## File reference

| File | Purpose |
|------|---------|
| `AgentjailExtension/Provider.swift` | `NETransparentProxyProvider` flow bridge |
| `AgentjailExtension/Info.plist` | Extension bundle metadata |
| `AgentjailExtension/AgentjailExtension.entitlements` | Extension entitlements |
| `AgentjailExtension/BridgingHeader.h` | ObjC bridge to the Go c-archive |
| `AgentjailTunnel/main.swift` | Host app / CLI shim — TunnelManager |
| `AgentjailTunnel/Info.plist` | Host app bundle metadata |
| `AgentjailTunnel/AgentjailTunnel.entitlements` | Host app entitlements |

## Troubleshooting

- **Extension not activating**: inspect `systemextensionsctl list` and Console.app
  filtered to `com.blinkerlm.agentjail.app.extension`; confirm the containing app
  remains in `/Applications`.
- **Present but inactive**: boot the guest with graphics and complete the Network
  Extensions approval. A headless session cannot substitute for it.
- **Tunnel start timeout**: inspect the AgentJail session socket and extension log;
  the CLI waits up to 30 seconds for the provider before failing visibly.
- **TLS fails before any request row**: check the fixed unified-log transport
  event for the attempted destination family. Strict verification must run with
  the default dual-stack posture and require a post-watermark `network_requests`
  row; a green lifecycle event alone does not prove that a flow reached MITM.
- **Release/test launch**: use `agentjail run --require-tunnel -- <agent>` and
  verify the post-watermark SQLite lifecycle. The ordinary `--tunnel` mode may
  fall back; terminal text is not proof that the extension carried the flow.
- **Strict smoke skips everything**: this is a failed verification. Clone
  `golden-macos-mitm`, confirm `[activated enabled]`, and rerun with `--strict`.
