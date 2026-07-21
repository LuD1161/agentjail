#!/usr/bin/env bash
#
# package-macos-dmg.sh - package build/AgentjailTunnel.app into a
# drag-install DMG (build/AgentjailTunnel.dmg).
#
# Packages whatever .app is already at APP_PATH (does not re-sign it).
# NOTARIZE=0 (default): package only - use for a local ad-hoc app.
# NOTARIZE=1: also notarize + staple the DMG (needs APPLE_ID, TEAM_ID,
# APP_PASSWORD in the environment; source the repo-root .env first). The
# app inside must already be Developer-ID signed + notarized.
#
# Usage:
#   scripts/package-macos-dmg.sh
#   NOTARIZE=1 scripts/package-macos-dmg.sh          # after sourcing .env
#   APP_PATH=/other/AgentjailTunnel.app DMG_PATH=/tmp/out.dmg scripts/package-macos-dmg.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO_ROOT/build"

APP_PATH="${APP_PATH:-$BUILD/AgentjailTunnel.app}"
DMG_PATH="${DMG_PATH:-$BUILD/AgentjailTunnel.dmg}"
VOLNAME="${VOLNAME:-AgentjailTunnel}"
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
    echo "==> notarizing DMG (needs APPLE_ID, TEAM_ID, APP_PASSWORD in env)"
    : "${APPLE_ID:?APPLE_ID not set - source .env or export it, or run with NOTARIZE=0}"
    : "${APP_PASSWORD:?APP_PASSWORD not set - source .env or export it, or run with NOTARIZE=0}"
    : "${TEAM_ID:?TEAM_ID not set - source .env or export it, or run with NOTARIZE=0}"
    xcrun notarytool submit "$DMG_PATH" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APP_PASSWORD" \
        --wait
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"
    echo "==> DMG notarized + stapled"
else
    echo "    Distributable DMG: re-run with NOTARIZE=1 (creds in env) to notarize + staple."
fi

echo "==> done: $DMG_PATH"
