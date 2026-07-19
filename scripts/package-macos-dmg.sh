#!/usr/bin/env bash
#
# package-macos-dmg.sh - package build/AgentjailTunnel.app into a
# drag-install DMG (build/AgentjailTunnel.dmg).
#
# Works with either the ad-hoc app produced by
# `NOTARIZE=0 scripts/build-macos-app.sh` (local test) or a Developer-ID
# signed + notarized app (`NOTARIZE=1`). This script does not sign,
# notarize, or staple anything - it only packages whatever .app is
# already at APP_PATH.
#
# Usage:
#   scripts/package-macos-dmg.sh
#   APP_PATH=/other/AgentjailTunnel.app DMG_PATH=/tmp/out.dmg scripts/package-macos-dmg.sh
#
# Manual step for a Developer-ID DMG meant for distribution (needs
# notarytool credentials - not run here, no creds in this environment):
#   xcrun notarytool submit build/AgentjailTunnel.dmg --apple-id "$APPLE_ID" \
#     --team-id "$TEAM_ID" --password "$APP_PASSWORD" --wait
#   xcrun stapler staple build/AgentjailTunnel.dmg
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO_ROOT/build"

APP_PATH="${APP_PATH:-$BUILD/AgentjailTunnel.app}"
DMG_PATH="${DMG_PATH:-$BUILD/AgentjailTunnel.dmg}"
VOLNAME="${VOLNAME:-AgentjailTunnel}"

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

echo "==> done: $DMG_PATH"
echo "    Manual next step for a distributable (Developer-ID) DMG, not run here (no creds):"
echo "      xcrun notarytool submit $DMG_PATH --apple-id \"\$APPLE_ID\" --team-id \"\$TEAM_ID\" --password \"\$APP_PASSWORD\" --wait"
echo "      xcrun stapler staple $DMG_PATH"
