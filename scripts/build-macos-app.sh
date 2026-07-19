#!/usr/bin/env bash
#
# build-macos-app.sh - build, assemble, and sign build/AgentjailTunnel.app
# from source. Idempotent: safe to re-run, each step overwrites its own
# outputs.
#
# Mirrors macos/README.md - keep the two in sync, this script is the
# executable form of that doc.
#
# Usage:
#   NOTARIZE=0 ./scripts/build-macos-app.sh    # build + ad-hoc sign only (default, offline-safe)
#   NOTARIZE=1 ./scripts/build-macos-app.sh    # build + Developer ID sign + notarize
#
# NOTARIZE=1 needs .env at the repo root with APPLE_ID, APP_PASSWORD,
# TEAM_ID (an app-specific password, not the Apple ID password), plus a
# Developer ID Application certificate in the login keychain. Never echo
# these values - they are sourced into the environment only.
#
# Does NOT copy the built app to /Applications or install the system
# extension - both require interactive user approval. See macos/README.md
# Step 7 for the manual install step after this script finishes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD="$REPO_ROOT/build"
APP="$BUILD/AgentjailTunnel.app"
EXT_ID="com.blinkerlm.agentjail.app.extension"
EXT="$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension"
TEAM_ID="Q98Z3744J2"
IDENTITY="Developer ID Application: Aseem Shrey ($TEAM_ID)"
NOTARIZE="${NOTARIZE:-0}"

echo "==> Step 1: building the Go cgo c-archive"
mkdir -p "$BUILD"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -buildmode=c-archive \
    -o "$BUILD/libagentjail_tunnel.a" \
    ./internal/tunnel/cbridge/

echo "==> Step 2: compiling the extension (NETransparentProxyProvider)"
mkdir -p "$BUILD/AgentjailExtension"
swiftc \
    -target arm64-apple-macos13.0 \
    -module-name AgentjailExtension \
    -import-objc-header macos/AgentjailExtension/BridgingHeader.h \
    -I "$BUILD/" \
    -L "$BUILD/" -lagentjail_tunnel -lbsm \
    -framework NetworkExtension \
    -framework Foundation \
    -o "$BUILD/AgentjailExtension/$EXT_ID" \
    macos/AgentjailExtension/main.swift macos/AgentjailExtension/Provider.swift

echo "==> Step 3: compiling the host app"
swiftc \
    -target arm64-apple-macos13.0 \
    -framework AppKit \
    -framework NetworkExtension \
    -framework SystemExtensions \
    -framework Foundation \
    -o "$BUILD/AgentjailTunnel" \
    macos/AgentjailTunnel/main.swift

echo "==> Step 4: assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$EXT/Contents/MacOS"

cp macos/AgentjailTunnel/Info.plist  "$APP/Contents/Info.plist"
cp "$BUILD/AgentjailTunnel"          "$APP/Contents/MacOS/AgentjailTunnel"

cp macos/AgentjailExtension/Info.plist  "$EXT/Contents/Info.plist"
cp "$BUILD/AgentjailExtension/$EXT_ID"  "$EXT/Contents/MacOS/$EXT_ID"

plutil -lint "$APP/Contents/Info.plist"
plutil -lint "$EXT/Contents/Info.plist"

if [ "$NOTARIZE" = "1" ]; then
    echo "==> Step 5: signing inner-to-outer with Developer ID ($IDENTITY)"
    codesign --force --timestamp --options runtime \
        --entitlements macos/AgentjailExtension/AgentjailExtension.entitlements \
        --sign "$IDENTITY" \
        "$EXT"

    codesign --force --timestamp --options runtime \
        --entitlements macos/AgentjailTunnel/AgentjailTunnel.entitlements \
        --sign "$IDENTITY" \
        "$APP"

    echo "==> Step 6: notarizing (set NOTARIZE=0 to skip)"
    if [ -f "$REPO_ROOT/.env" ]; then
        # shellcheck disable=SC1091
        source "$REPO_ROOT/.env"
    fi
    : "${APPLE_ID:?APPLE_ID not set - add it to .env or export it, or run with NOTARIZE=0}"
    : "${APP_PASSWORD:?APP_PASSWORD not set - add it to .env or export it, or run with NOTARIZE=0}"
    : "${TEAM_ID:?TEAM_ID not set - add it to .env or export it, or run with NOTARIZE=0}"

    ZIP="$BUILD/AgentjailTunnel.zip"
    rm -f "$ZIP"
    ditto -c -k --keepParent "$APP" "$ZIP"

    xcrun notarytool submit "$ZIP" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APP_PASSWORD" \
        --wait

    xcrun stapler staple "$APP"

    echo "==> assessing Gatekeeper policy"
    spctl -a -vv -t exec "$APP" || true
else
    echo "==> Step 5: ad-hoc signing (NOTARIZE=0, local-only, no Developer ID)"
    codesign -s - --force --options runtime \
        --entitlements macos/AgentjailExtension/AgentjailExtension.entitlements \
        "$EXT"

    codesign -s - --force --options runtime \
        --entitlements macos/AgentjailTunnel/AgentjailTunnel.entitlements \
        "$APP"

    echo "==> Step 6: notarization skipped (NOTARIZE=0)"
fi

echo "==> verifying signature"
codesign --verify --verbose=2 "$APP" || true

echo "==> done: $APP"
echo "    Manual next step (needs user approval, not scripted):"
echo "      $APP/Contents/MacOS/AgentjailTunnel install"
