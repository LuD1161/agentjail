# AgentJail macOS Transparent Tunnel

This directory contains the macOS Network Extension that captures all agent
network traffic at the OS packet level — no proxy env-vars, no per-process
configuration needed.

## Architecture

```
Agent process
    |
    v (all IP packets)
NEPacketTunnelProvider  (TunnelExtension — runs as a system extension process)
    |
    |  AgentjailTunnelHandlePacket() / AgentjailTunnelReadPacket()
    v
libagentjail_tunnel.a   (Go static library — linked into the extension binary)
    |
    v (policy-checked, optionally TLS-inspected)
upstream network
```

DNS queries are hijacked by pointing the virtual interface's DNS resolver at
`10.78.0.1` (the Go gateway VIP) so every DNS lookup can be logged and
optionally blocked before it hits the wire.

The host app (`AgentjailTunnel.app`) calls `NETunnelProviderManager` APIs to
install and start the extension.  `agentjail-shield` can drive the same
activate/deactivate flow via the CLI shim compiled from `AgentjailTunnel/main.swift`.

## Prerequisites

- macOS 12 Monterey or later
- Xcode 14+ **or** the Command Line Tools with `swiftc`
- An Apple Developer account enrolled in the Developer ID programme
- Team ID: `Q98Z3744J2` (already baked into the entitlement `$(TeamIdentifierPrefix)`)
- A provisioning profile that grants:
  - `com.apple.developer.networking.networkextension` → `packet-tunnel-provider`
  - `com.apple.developer.system-extension.install`
  - App Group `Q98Z3744J2.com.openclaw.agentjail`

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
cd internal/tunnel   # wherever the Go gateway lives
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -buildmode=c-archive \
    -o ../../build/libagentjail_tunnel.a .
```

For a universal (arm64 + x86_64) library:

```sh
# Build each arch
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64  go build -buildmode=c-archive -o /tmp/lib_arm64.a .
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64  go build -buildmode=c-archive -o /tmp/lib_amd64.a .
lipo -create /tmp/lib_arm64.a /tmp/lib_amd64.a -output build/libagentjail_tunnel.a
cp /tmp/lib_arm64.h build/libagentjail_tunnel.h   # header is arch-independent
```

## Step 2 — Build the Swift extension

### Using swiftc directly (quick iteration)

```sh
TEAM_ID=Q98Z3744J2
BUILD=build/TunnelExtension

mkdir -p $BUILD

swiftc \
    -target arm64-apple-macos12.0 \
    -module-name TunnelExtension \
    -import-objc-header macos/TunnelExtension/AgentjailTunnel-Bridging-Header.h \
    -L build/ -lagentjail_tunnel \
    -framework NetworkExtension \
    -framework Foundation \
    -o $BUILD/TunnelExtension \
    macos/TunnelExtension/PacketTunnelProvider.swift
```

### Using xcodebuild (recommended for distribution)

Create an Xcode project (or use the provided one when available):

```sh
xcodebuild \
    -scheme TunnelExtension \
    -configuration Release \
    -derivedDataPath build/xcode \
    CODE_SIGN_IDENTITY="Developer ID Application" \
    DEVELOPMENT_TEAM=$TEAM_ID \
    build
```

## Step 3 — Build the host app

```sh
swiftc \
    -target arm64-apple-macos12.0 \
    -framework NetworkExtension \
    -framework Foundation \
    -o build/AgentjailTunnel \
    macos/AgentjailTunnel/main.swift
```

## Step 4 — Assemble the app bundle

The system extension must be embedded inside the host app at:

```
AgentjailTunnel.app/
└── Contents/
    ├── Info.plist
    ├── MacOS/
    │   └── AgentjailTunnel
    └── Library/
        └── SystemExtensions/
            └── com.openclaw.agentjail.tunnel.extension.systemextension/
                └── Contents/
                    ├── Info.plist
                    └── MacOS/
                        └── TunnelExtension
```

```sh
APP=build/AgentjailTunnel.app
EXT=$APP/Contents/Library/SystemExtensions/com.openclaw.agentjail.tunnel.extension.systemextension

mkdir -p $APP/Contents/MacOS
mkdir -p $EXT/Contents/MacOS

cp macos/AgentjailTunnel/Info.plist $APP/Contents/
cp build/AgentjailTunnel             $APP/Contents/MacOS/

cp macos/TunnelExtension/Info.plist  $EXT/Contents/
cp build/TunnelExtension             $EXT/Contents/MacOS/
```

## Step 5 — Sign

Both the extension and the host app must be signed with the same Developer ID
and the matching provisioning profiles.

```sh
TEAM_ID=Q98Z3744J2
IDENTITY="Developer ID Application: Aseem Shrey ($TEAM_ID)"

# Sign the extension first (inner-to-outer rule).
codesign --force --timestamp \
    --entitlements macos/TunnelExtension/TunnelExtension.entitlements \
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
spctl --assess --type execute $APP
```

## Step 6 — Install the system extension

Run the host app once; it will call `OSSystemExtensionManager` to prompt the
user to approve the extension in System Settings > Privacy & Security.

Alternatively, for development (SIP disabled):

```sh
# Copy the .systemextension bundle to the correct location then activate.
systemextensionsctl list
# Look for com.openclaw.agentjail.tunnel.extension
```

## Step 7 — Activate / deactivate the tunnel

```sh
# Activate (creates the VPN configuration and starts the tunnel).
./build/AgentjailTunnel activate

# Deactivate.
./build/AgentjailTunnel deactivate
```

`agentjail-shield` can exec these commands or call `TunnelManager` directly
when the two targets are linked together.

## File reference

| File | Purpose |
|------|---------|
| `TunnelExtension/PacketTunnelProvider.swift` | NEPacketTunnelProvider subclass — packet loop, Go bridge |
| `TunnelExtension/Info.plist` | Extension bundle metadata |
| `TunnelExtension/TunnelExtension.entitlements` | Extension entitlements |
| `TunnelExtension/AgentjailTunnel-Bridging-Header.h` | ObjC bridge to libagentjail_tunnel.h |
| `AgentjailTunnel/main.swift` | Host app / CLI shim — TunnelManager |
| `AgentjailTunnel/Info.plist` | Host app bundle metadata |
| `AgentjailTunnel/AgentjailTunnel.entitlements` | Host app entitlements |

## Virtual network layout

| Address | Role |
|---------|------|
| `10.78.0.1` | Go gateway VIP (DNS resolver, default gateway) |
| `10.78.0.2` | Virtual client address presented to the OS |
| `0.0.0.0/0` | Included route — all traffic goes through the tunnel |

## Troubleshooting

- **Extension not activating**: check Console.app filtered to `com.openclaw.agentjail.tunnel` for errors from `NEPacketTunnelProvider`.
- **`AgentjailTunnelStart` returns non-zero**: the Go gateway failed to bind; check for port conflicts on `10.78.0.1`.
- **DNS not resolving**: confirm `matchDomains = [""]` is set; the empty string is the catch-all magic value.
- **Packet loop CPU spike**: normal at ~5k pkt/s; `usleep(500)` in `writeToPacketFlow` bounds idle CPU to < 0.1%.
