#!/usr/bin/env bash
#
# package-macos-dmg.sh - package build/AgentJail.app into a
# drag-install DMG (build/AgentJail.dmg).
#
# Packages whatever .app is already at APP_PATH (does not re-sign it).
# NOTARIZE=0 (default): package only - use for a local ad-hoc app.
# NOTARIZE=1: also notarize + staple the DMG (using NOTARY_PROFILE or an
# App Store Connect API key). The
# app inside must already be Developer-ID signed + notarized.
#
# Usage:
#   scripts/package-macos-dmg.sh
#   NOTARY_PROFILE=agentjail-notary NOTARIZE=1 scripts/package-macos-dmg.sh
#   APP_PATH=/other/AgentJail.app DMG_PATH=/tmp/out.dmg scripts/package-macos-dmg.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO_ROOT/build"

APP_PATH="${APP_PATH:-$BUILD/AgentJail.app}"
DMG_PATH="${DMG_PATH:-$BUILD/AgentJail.dmg}"
VOLNAME="${VOLNAME:-AgentJail}"
NOTARIZE="${NOTARIZE:-0}"

if [ ! -d "$APP_PATH" ]; then
    echo "error: $APP_PATH not found - run 'make macos-app' first" >&2
    exit 1
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

echo "==> staging DMG contents in $STAGING"
ditto "$APP_PATH" "$STAGING/$(basename "$APP_PATH")"
ln -s /Applications "$STAGING/Applications"

echo "==> building $DMG_PATH"
rm -f "$DMG_PATH"
hdiutil create \
    -volname "$VOLNAME" \
    -srcfolder "$STAGING" \
    -format UDZO \
    -fs HFS+ \
    -ov \
    "$DMG_PATH"

echo "==> verifying $DMG_PATH"
hdiutil verify "$DMG_PATH"

if [ "$NOTARIZE" = "1" ]; then
    auth=()
    if [ -n "${NOTARY_PROFILE:-}" ]; then
        auth=(--keychain-profile "$NOTARY_PROFILE")
    elif [ -n "${ASC_KEY:-}" ] && [ -n "${ASC_KEY_ID:-}" ] && [ -n "${ASC_ISSUER_ID:-}" ]; then
        [ -f "$ASC_KEY" ] || { echo "error: ASC_KEY not found: $ASC_KEY" >&2; exit 1; }
        auth=(--key "$ASC_KEY" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID")
    else
        echo "error: NOTARIZE=1 requires NOTARY_PROFILE or ASC_KEY + ASC_KEY_ID + ASC_ISSUER_ID" >&2
        exit 1
    fi
    echo "==> notarizing DMG"
    xcrun notarytool submit "$DMG_PATH" "${auth[@]}" --wait
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"
    echo "==> DMG notarized + stapled"
else
    echo "    Local DMG only: re-run with NOTARIZE=1 after the app is Developer ID signed and notarized."
fi

echo "==> done: $DMG_PATH"
