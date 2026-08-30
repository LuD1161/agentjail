#!/usr/bin/env bash
# Build, assemble, sign, and optionally notarize the unified AgentJail.app.
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repo_root="$(cd -- "$script_dir/.." && pwd -P)"
readonly build_root="$repo_root/build"
readonly app_path="$build_root/AgentJail.app"
readonly app_id="com.blinkerlm.agentjail"
readonly extension_id="$app_id.extension"
readonly team_id="${TEAM_ID:-Q98Z3744J2}"
readonly minimum_system_version="13.0"
readonly signing_mode="${SIGNING_MODE:-adhoc}"
readonly notarize="${NOTARIZE:-0}"
readonly identity="${APPLE_SIGNING_IDENTITY:-Developer ID Application: Aseem Shrey ($team_id)}"

readonly codesign_binary="/usr/bin/codesign"
readonly lipo_binary="/usr/bin/lipo"
readonly plutil_binary="/usr/bin/plutil"
readonly plist_buddy="/usr/libexec/PlistBuddy"
readonly security_binary="/usr/bin/security"
readonly date_binary="/bin/date"
readonly xcrun_binary="/usr/bin/xcrun"
readonly ditto_binary="/usr/bin/ditto"
readonly iconutil_binary="/usr/bin/iconutil"
readonly sips_binary="/usr/bin/sips"
readonly mkdir_binary="/bin/mkdir"
readonly cp_binary="/bin/cp"
readonly rm_binary="/bin/rm"
readonly mv_binary="/bin/mv"

fail() {
  printf 'build-macos-app: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing required file: $1"
}

require_executable() {
  [[ -x "$1" ]] || fail "missing required executable: $1"
}

plist_value() {
  "$plist_buddy" -c "Print :$2" "$1" 2>/dev/null
}

require_plist_value() {
  local actual
  actual="$(plist_value "$1" "$2")" || fail "missing $2 in $1"
  [[ "$actual" == "$3" ]] || fail "$2 must be $3 in $1, got $actual"
}

require_plist_array_value() {
  local values value
  values="$(plist_value "$1" "$2")" || fail "missing $2 in $1"
  while IFS= read -r value; do
    value="${value#"${value%%[![:space:]]*}"}"
    [[ "$value" == "$3" ]] && return
  done <<< "$values"
  fail "$2 must contain $3 in $1"
}

resolve_version() {
  local raw_version
  raw_version="${MACOS_APP_VERSION:-$(git -C "$repo_root" describe --tags --abbrev=0 2>/dev/null || printf '0.1.0')}"
  app_version="${raw_version#v}"
  [[ "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "MACOS_APP_VERSION must be X.Y.Z, got $app_version"
  app_build="${MACOS_BUILD_NUMBER:-$(git -C "$repo_root" rev-list --count HEAD)}"
  [[ "$app_build" =~ ^[1-9][0-9]*$ ]] || fail "MACOS_BUILD_NUMBER must be a positive integer, got $app_build"
}

resolve_toolchain() {
  developer_dir="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
  if [[ ! -d "$developer_dir" ]]; then
    developer_dir="$(/usr/bin/xcode-select -p)"
  fi
  swiftc_binary="$(DEVELOPER_DIR="$developer_dir" "$xcrun_binary" --sdk macosx --find swiftc)"
  macos_sdk="$(DEVELOPER_DIR="$developer_dir" "$xcrun_binary" --sdk macosx --show-sdk-path)"
  require_executable "$swiftc_binary"
  [[ -d "$macos_sdk" ]] || fail "macOS SDK not found: $macos_sdk"
}

validate_work_root() {
  [[ "$1" == "$build_root"/.macos-product.* ]] || fail "unsafe work root: $1"
  [[ -d "$1" && ! -L "$1" ]] || fail "work root is not a real directory: $1"
}

cleanup() {
  local status=$?
  if [[ ${completed:-0} -eq 1 ]]; then
    validate_work_root "$work_root"
    "$rm_binary" -rf -- "$work_root"
    if [[ -n "${approval_root:-}" && -d "$approval_root" && "$approval_root" == /private/tmp/agentjail-macos-approval-unified.* ]]; then
      "$rm_binary" -rf -- "$approval_root"
    fi
  else
    printf 'build-macos-app: preserved failed work at %s\n' "${work_root:-not-created}" >&2
    [[ -z "${approval_root:-}" ]] || printf 'build-macos-app: preserved approval build at %s\n' "$approval_root" >&2
  fi
  exit "$status"
}

go_arch_for() {
  case "$1" in
    arm64) printf 'arm64\n' ;;
    x86_64) printf 'amd64\n' ;;
    *) fail "unsupported macOS architecture: $1" ;;
  esac
}

build_extension_arch() {
  local swift_arch=$1
  local go_arch
  local arch_root="$work_root/extension-$swift_arch"
  go_arch="$(go_arch_for "$swift_arch")"
  "$mkdir_binary" -p -- "$arch_root"

  env \
    MACOSX_DEPLOYMENT_TARGET="$minimum_system_version" \
    CGO_ENABLED=1 GOOS=darwin GOARCH="$go_arch" \
    CGO_CFLAGS="-arch $swift_arch -mmacosx-version-min=$minimum_system_version" \
    CGO_LDFLAGS="-arch $swift_arch -mmacosx-version-min=$minimum_system_version" \
    go build -trimpath -buildmode=c-archive \
      -o "$arch_root/libagentjail_tunnel.a" \
      "$repo_root/internal/tunnel/cbridge/"

  env \
    DEVELOPER_DIR="$developer_dir" \
    SDKROOT="$macos_sdk" \
    TMPDIR="$work_root/tmp-$swift_arch" \
    CLANG_MODULE_CACHE_PATH="$work_root/clang-modules-$swift_arch" \
    SWIFT_MODULE_CACHE_PATH="$work_root/swift-modules-$swift_arch" \
    "$swiftc_binary" \
      -sdk "$macos_sdk" \
      -target "$swift_arch-apple-macosx$minimum_system_version" \
      -O -whole-module-optimization \
      -module-name AgentjailExtension \
      -import-objc-header "$repo_root/macos/AgentjailExtension/BridgingHeader.h" \
      -I "$arch_root" -L "$arch_root" -lagentjail_tunnel -lbsm \
      -framework NetworkExtension -framework Foundation \
      -o "$arch_root/$extension_id" \
      "$repo_root/macos/AgentjailExtension/main.swift" \
      "$repo_root/macos/AgentjailExtension/Provider.swift"
}

build_cli_arch() {
  local swift_arch=$1
  local go_arch
  local arch_root="$work_root/cli-$swift_arch"
  go_arch="$(go_arch_for "$swift_arch")"
  "$mkdir_binary" -p -- "$arch_root"
  local ldflags="-s -w -X github.com/LuD1161/agentjail/internal/buildinfo.Version=v$app_version"
  if [[ -n "${POSTHOG_KEY:-}" ]]; then
    ldflags="$ldflags -X github.com/LuD1161/agentjail/internal/telemetry.apiKey=$POSTHOG_KEY"
  fi
  if [[ -n "${SELFUPDATE_SIGNING_PUB_KEY:-}" ]]; then
    ldflags="$ldflags -X github.com/LuD1161/agentjail/internal/selfupdate.SigningPubKey=$SELFUPDATE_SIGNING_PUB_KEY"
  fi
  for binary in agentjail agentjail-hook; do
    env CGO_ENABLED=0 GOOS=darwin GOARCH="$go_arch" \
      go build -trimpath \
        -ldflags "$ldflags" \
        -o "$arch_root/$binary" "$repo_root/cmd/$binary"
  done
}

build_app_icon() {
  local source=$1
  local destination=$2
  local iconset="$work_root/AgentJail.iconset"
  "$mkdir_binary" -p -- "$iconset"
  local name pixels
  while read -r name pixels; do
    "$sips_binary" -z "$pixels" "$pixels" "$source" --out "$iconset/$name.png" >/dev/null
  done <<'SIZES'
icon_16x16 16
icon_16x16@2x 32
icon_32x32 32
icon_32x32@2x 64
icon_128x128 128
icon_128x128@2x 256
icon_256x256 256
icon_256x256@2x 512
icon_512x512 512
icon_512x512@2x 1024
SIZES
  "$iconutil_binary" -c icns "$iconset" -o "$destination"
}

verify_profile() {
  local profile=$1
  local expected_id=$2
  local decoded="$work_root/$(basename "$profile").plist"
  local expiration expiration_epoch current_epoch
  "$security_binary" cms -D -i "$profile" > "$decoded"
  require_plist_value "$decoded" "TeamIdentifier:0" "$team_id"
  require_plist_value "$decoded" "ProvisionsAllDevices" "true"
  require_plist_value "$decoded" "Entitlements:com.apple.application-identifier" "$team_id.$expected_id"
  require_plist_array_value "$decoded" "Entitlements:com.apple.developer.networking.networkextension" "app-proxy-provider-systemextension"
  expiration="$("$plutil_binary" -extract ExpirationDate raw "$decoded")" \
    || fail "missing ExpirationDate in $decoded"
  expiration_epoch="$("$date_binary" -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$expiration" '+%s')" \
    || fail "invalid ExpirationDate in $decoded"
  current_epoch="$("$date_binary" -u '+%s')"
  (( expiration_epoch > current_epoch )) || fail "provisioning profile expired: $profile"
}

sign_bundle() {
  local app=$1
  local extension="$app/Contents/Library/SystemExtensions/$extension_id.systemextension"
  local cli_root="$app/Contents/Resources/bin"
  local sign_args=()

  case "$signing_mode" in
    adhoc)
      [[ "$notarize" == "0" ]] || fail "NOTARIZE=1 requires SIGNING_MODE=developer-id"
      sign_args=(--sign - --timestamp=none)
      ;;
    developer-id)
      sign_args=(--sign "$identity" --timestamp)
      local profile_dir="${PROFILE_DIR:-$repo_root/.secrets/profiles}"
      local app_profile="$profile_dir/$app_id.provisionprofile"
      local extension_profile="$profile_dir/$extension_id.provisionprofile"
      require_file "$app_profile"
      require_file "$extension_profile"
      verify_profile "$app_profile" "$app_id"
      verify_profile "$extension_profile" "$extension_id"
      "$cp_binary" "$app_profile" "$app/Contents/embedded.provisionprofile"
      "$cp_binary" "$extension_profile" "$extension/Contents/embedded.provisionprofile"
      ;;
    *) fail "SIGNING_MODE must be adhoc or developer-id" ;;
  esac

  for binary in "$cli_root/agentjail" "$cli_root/agentjail-hook"; do
    "$codesign_binary" --force --options runtime "${sign_args[@]}" "$binary"
  done
  "$codesign_binary" --force --options runtime \
    --entitlements "$repo_root/macos/AgentjailExtension/AgentjailExtension.entitlements" \
    "${sign_args[@]}" "$extension"
  "$codesign_binary" --force --options runtime \
    --entitlements "$repo_root/macos/AgentJail/AgentJail.entitlements" \
    "${sign_args[@]}" "$app"
}

verify_bundle() {
  local app=$1
  local extension="$app/Contents/Library/SystemExtensions/$extension_id.systemextension"
  "$plutil_binary" -lint "$app/Contents/Info.plist" "$extension/Contents/Info.plist" >/dev/null
  require_plist_value "$app/Contents/Info.plist" CFBundleIdentifier "$app_id"
  require_plist_value "$app/Contents/Info.plist" CFBundleExecutable AgentJail
  require_plist_value "$extension/Contents/Info.plist" CFBundleIdentifier "$extension_id"
  require_plist_value "$app/Contents/Info.plist" CFBundleShortVersionString "$app_version"
  require_plist_value "$extension/Contents/Info.plist" CFBundleShortVersionString "$app_version"
  require_plist_value "$app/Contents/Info.plist" CFBundleVersion "$app_build"
  require_plist_value "$extension/Contents/Info.plist" CFBundleVersion "$app_build"

  for binary in \
    "$app/Contents/MacOS/AgentJail" \
    "$extension/Contents/MacOS/$extension_id" \
    "$app/Contents/Resources/bin/agentjail" \
    "$app/Contents/Resources/bin/agentjail-hook"; do
    local architectures
    architectures="$("$lipo_binary" -archs "$binary")"
    [[ "$architectures" == "arm64 x86_64" || "$architectures" == "x86_64 arm64" ]] \
      || fail "expected universal binary, got '$architectures': $binary"
    "$codesign_binary" --verify --strict --verbose=2 "$binary"
  done
  "$codesign_binary" --verify --strict --verbose=2 "$extension"
  "$codesign_binary" --verify --strict --verbose=2 "$app"
  "$codesign_binary" --verify --deep --strict --verbose=2 "$app"
}

notarize_bundle() {
  local app=$1
  local archive="$work_root/AgentJail-notarization.zip"
  local auth=()
  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    auth=(--keychain-profile "$NOTARY_PROFILE")
  elif [[ -n "${ASC_KEY:-}" && -n "${ASC_KEY_ID:-}" && -n "${ASC_ISSUER_ID:-}" ]]; then
    require_file "$ASC_KEY"
    auth=(--key "$ASC_KEY" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID")
  else
    fail "NOTARIZE=1 requires NOTARY_PROFILE or ASC_KEY + ASC_KEY_ID + ASC_ISSUER_ID"
  fi
  "$ditto_binary" -c -k --keepParent "$app" "$archive"
  "$xcrun_binary" notarytool submit "$archive" "${auth[@]}" --wait
  "$xcrun_binary" stapler staple "$app"
  "$xcrun_binary" stapler validate "$app"
  /usr/sbin/spctl -a -vvv -t exec "$app"
}

for executable in \
  "$codesign_binary" "$lipo_binary" "$plutil_binary" "$plist_buddy" \
  "$security_binary" "$xcrun_binary" "$ditto_binary" "$mkdir_binary" \
  "$iconutil_binary" "$sips_binary" "$cp_binary" "$rm_binary" "$mv_binary"; do
  require_executable "$executable"
done
require_file "$repo_root/macos/AgentJail/Info.plist"
require_file "$repo_root/macos/AgentJail/AgentJail.entitlements"
require_file "$repo_root/macos/AgentjailExtension/Info.plist"
require_file "$repo_root/macos/AgentjailExtension/AgentjailExtension.entitlements"
require_file "$repo_root/assets/social/avatar-jail-1024.png"
require_file "$repo_root/LICENSE"
require_file "$repo_root/NOTICE"
require_file "$repo_root/THIRD_PARTY_LICENSES"

if [[ "${1:-}" == "--verify-only" ]]; then
  (( $# == 2 )) || fail "usage: $0 --verify-only /path/to/AgentJail.app"
  app_version="$(plist_value "$2/Contents/Info.plist" CFBundleShortVersionString)" \
    || fail "could not read app version from $2"
  app_build="$(plist_value "$2/Contents/Info.plist" CFBundleVersion)" \
    || fail "could not read app build from $2"
  verify_bundle "$2"
  printf 'build-macos-app: verified %s\n' "$2"
  exit 0
fi
(( $# == 0 )) || fail "usage: $0 [--verify-only /path/to/AgentJail.app]"

"$mkdir_binary" -p -- "$build_root"
[[ ! -L "$build_root" ]] || fail "build root must not be a symlink"
work_root="$(mktemp -d "$build_root/.macos-product.XXXXXXXX")"
approval_root="$(mktemp -d /private/tmp/agentjail-macos-approval-unified.XXXXXXXX)"
completed=0
trap cleanup EXIT
resolve_version
resolve_toolchain
printf 'build-macos-app: version=%s build=%s signing=%s\n' "$app_version" "$app_build" "$signing_mode"

APPROVAL_ARTIFACT_ROOT="$approval_root" "$repo_root/scripts/build-macos-approval-app.sh"
for architecture in arm64 x86_64; do
  "$mkdir_binary" -p -- "$work_root/tmp-$architecture"
  build_extension_arch "$architecture"
  build_cli_arch "$architecture"
done

stage_app="$work_root/AgentJail.app"
stage_extension="$stage_app/Contents/Library/SystemExtensions/$extension_id.systemextension"
"$mkdir_binary" -p -- \
  "$stage_app/Contents/MacOS" \
  "$stage_app/Contents/Resources/bin" \
  "$stage_extension/Contents/MacOS"
"$cp_binary" "$repo_root/macos/AgentJail/Info.plist" "$stage_app/Contents/Info.plist"
build_app_icon "$repo_root/assets/social/avatar-jail-1024.png" "$stage_app/Contents/Resources/AgentJail.icns"
for attribution in LICENSE NOTICE THIRD_PARTY_LICENSES; do
  "$cp_binary" "$repo_root/$attribution" "$stage_app/Contents/Resources/$attribution"
done
"$cp_binary" "$repo_root/macos/AgentjailExtension/Info.plist" "$stage_extension/Contents/Info.plist"
"$cp_binary" "$approval_root/AgentjailApproval.app/Contents/MacOS/AgentjailApproval" "$stage_app/Contents/MacOS/AgentJail"
for asset in agent-claude.svg agent-codex.svg agent-codex-light.svg agent-cursor.svg server-linear.svg server-chrome.svg server-context7.ico; do
  "$cp_binary" "$approval_root/AgentjailApproval.app/Contents/Resources/$asset" "$stage_app/Contents/Resources/$asset"
done
"$lipo_binary" -create \
  "$work_root/extension-arm64/$extension_id" \
  "$work_root/extension-x86_64/$extension_id" \
  -output "$stage_extension/Contents/MacOS/$extension_id"
for binary in agentjail agentjail-hook; do
  "$lipo_binary" -create \
    "$work_root/cli-arm64/$binary" "$work_root/cli-x86_64/$binary" \
    -output "$stage_app/Contents/Resources/bin/$binary"
done
for plist in "$stage_app/Contents/Info.plist" "$stage_extension/Contents/Info.plist"; do
  "$plist_buddy" -c "Set :CFBundleShortVersionString $app_version" "$plist"
  "$plist_buddy" -c "Set :CFBundleVersion $app_build" "$plist"
done

sign_bundle "$stage_app"
verify_bundle "$stage_app"
if [[ "$notarize" == "1" ]]; then
  notarize_bundle "$stage_app"
  verify_bundle "$stage_app"
fi

if [[ -e "$app_path" || -L "$app_path" ]]; then
  [[ "$app_path" == "$build_root/AgentJail.app" && ! -L "$app_path" ]] || fail "unsafe app output path: $app_path"
  "$rm_binary" -rf -- "$app_path"
fi
"$mv_binary" "$stage_app" "$app_path"
completed=1
printf 'build-macos-app: app=%s\n' "$app_path"
if [[ "$signing_mode" == "adhoc" ]]; then
  printf 'build-macos-app: local-only ad-hoc build; use SIGNING_MODE=developer-id NOTARIZE=1 for distribution\n'
fi
