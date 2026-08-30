#!/usr/bin/env bash
# Build and locally sign the standalone AgentJail Approval companion.
set -euo pipefail

readonly product_name="AgentjailApproval"
readonly bundle_identifier="com.blinkerlm.agentjail.approval"
readonly minimum_system_version="13.0"
readonly task_prefix="/private/tmp/agentjail-macos-approval-"
readonly codesign_binary="/usr/bin/codesign"
readonly lipo_binary="/usr/bin/lipo"
readonly plutil_binary="/usr/bin/plutil"
readonly plist_buddy="/usr/libexec/PlistBuddy"
readonly xcode_select="/usr/bin/xcode-select"
readonly xcrun_binary="/usr/bin/xcrun"
readonly mktemp_binary="/usr/bin/mktemp"
readonly find_binary="/usr/bin/find"
readonly sort_binary="/usr/bin/sort"
readonly grep_binary="/usr/bin/grep"
readonly tr_binary="/usr/bin/tr"
readonly otool_binary="/usr/bin/otool"
readonly shasum_binary="/usr/bin/shasum"
readonly awk_binary="/usr/bin/awk"
readonly mkdir_binary="/bin/mkdir"
readonly cp_binary="/bin/cp"
readonly rm_binary="/bin/rm"
readonly mv_binary="/bin/mv"
readonly basename_binary="/usr/bin/basename"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
package_root="$repo_root/macos/AgentjailApproval"
info_plist="$package_root/Resources/Info.plist"
entitlements="$package_root/Resources/AgentjailApproval.entitlements"
app_resources="$package_root/Sources/AgentjailApprovalApp/Resources"
default_artifact_root="$repo_root/build/macos-approval"
default_build_root="$repo_root/build"
artifact_root="${APPROVAL_ARTIFACT_ROOT:-$default_artifact_root}"

fail() {
  printf 'build-macos-approval-app: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing required file: $1"
}

require_executable() {
  [[ -x "$1" ]] || fail "missing required executable: $1"
}

reject_unresolved_path() {
  [[ "$1" == /* ]] || fail "path must be absolute: $1"
  case "/$1/" in
    */../*) fail "path must not contain a parent traversal: $1" ;;
  esac
}

resolve_artifact_root() {
  local candidate=$1
  local canonical

  reject_unresolved_path "$candidate"
  case "$candidate" in
    "$default_artifact_root")
      [[ ! -e "$default_build_root" || ( -d "$default_build_root" && ! -L "$default_build_root" ) ]] || fail "build root must be a non-symlink directory: $default_build_root"
      "$mkdir_binary" -p -- "$default_build_root"
      [[ "$(cd -P -- "$default_build_root" && pwd -P)" == "$default_build_root" ]] || fail "build root escapes the repository: $default_build_root"
      [[ ! -e "$default_artifact_root" || ( -d "$default_artifact_root" && ! -L "$default_artifact_root" ) ]] || fail "approval artifact root must be a non-symlink directory: $default_artifact_root"
      "$mkdir_binary" -p -- "$default_artifact_root"
      ;;
    "$task_prefix"*)
      [[ -d "$candidate" && ! -L "$candidate" ]] || fail "task artifact root must be an existing non-symlink directory: $candidate"
      ;;
    *) fail "artifact root must be $default_artifact_root or an existing $task_prefix* directory: $candidate" ;;
  esac

  canonical="$(cd -P -- "$candidate" && pwd -P)"
  case "$canonical" in
    "$default_artifact_root"|"$task_prefix"*) ;;
    *) fail "artifact root escapes its allowed boundary: $candidate" ;;
  esac
  printf '%s\n' "$canonical"
}

validate_build_directory() {
  case "$1" in
    "$artifact_root"/.build.*|"$task_prefix"verify.*) ;;
    *) fail "refusing to remove an invalid task directory: $1" ;;
  esac
  [[ ! -L "$1" ]] || fail "refusing to remove a symlinked task directory: $1"
  [[ "$(cd -P -- "$1" && pwd -P)" == "$1" ]] || fail "task directory escapes its allowed boundary: $1"
}

normalize_empty_dictionary() {
  local input=$1
  local normalized=$2
  "$plutil_binary" -lint "$input" >/dev/null
  "$plutil_binary" -convert json -o "$normalized" "$input"
  [[ "$("$tr_binary" -d '[:space:]' < "$normalized")" == "{}" ]] || fail "expected an exact empty entitlement dictionary: $input"
}

require_plist_value() {
  local plist=$1
  local key=$2
  local expected=$3
  local actual
  actual="$("$plist_buddy" -c "Print :$key" "$plist")" || fail "missing $key in $plist"
  [[ "$actual" == "$expected" ]] || fail "$key must be $expected, got $actual"
}

verify_package_manifest() {
  local manifest_hash

  require_file "$package_root/Package.swift"
  # shellcheck disable=SC2016
  manifest_hash="$("$shasum_binary" -a 256 "$package_root/Package.swift" | "$awk_binary" '{print $1}')"
  [[ "$manifest_hash" == "152e2a2e731cb84dc540cf5e4275bb40dade7fa27a17a0a627d4432fdabd2765" ]] || fail "Package.swift changed; review direct packaging inputs before continuing"
  "$grep_binary" -Fqx '// swift-tools-version: 6.0' "$package_root/Package.swift" || fail "unexpected Swift tools version"
  "$grep_binary" -Fq 'name: "AgentjailApproval",' "$package_root/Package.swift" || fail "missing approval package identity"
  "$grep_binary" -Fq '.macOS(.v13)' "$package_root/Package.swift" || fail "package must target macOS 13"
  "$grep_binary" -Fq 'name: "AgentjailApprovalCore"' "$package_root/Package.swift" || fail "missing Core product or target"
  "$grep_binary" -Fq '.executable(' "$package_root/Package.swift" || fail "missing executable product"
  "$grep_binary" -Fq 'targets: ["AgentjailApprovalApp"]' "$package_root/Package.swift" || fail "executable product must use AgentjailApprovalApp"
  "$grep_binary" -Fq '.executableTarget(' "$package_root/Package.swift" || fail "missing approval app executable target"
  "$grep_binary" -Fq 'dependencies: ["AgentjailApprovalCore"]' "$package_root/Package.swift" || fail "approval app must depend only on Core"
  "$grep_binary" -Fq 'resources: [.process("Resources")]' "$package_root/Package.swift" || fail "approval app must process its bundled resources"
  if "$grep_binary" -Eq '\.package\(|plugins:|unsafeFlags' "$package_root/Package.swift"; then
    fail "Package.swift contains an unsupported packaging input"
  fi
}

assert_standalone_binary() {
  local binary=$1
  local dependencies

  dependencies="$("$otool_binary" -L "$binary" | "$grep_binary" -E '^[[:space:]]')"
  if printf '%s\n' "$dependencies" | "$grep_binary" -Eq 'AgentjailApprovalCore|/private/tmp/agentjail-macos-approval-'; then
    fail "executable has an unexpected Core or task-path dylib dependency: $binary"
  fi
}

resolve_toolchain() {
  local candidate
  local candidates=()
  selected_developer_dir=""
  swiftc_binary=""
  macos_sdk=""

  if [[ -n "${DEVELOPER_DIR:-}" ]]; then
    candidates+=("$DEVELOPER_DIR")
  fi
  candidates+=("/Applications/Xcode.app/Contents/Developer")
  if candidate="$("$xcode_select" -p 2>/dev/null)"; then :; else candidate=""; fi
  [[ -n "$candidate" ]] && candidates+=("$candidate")

  for candidate in "${candidates[@]}"; do
    [[ -d "$candidate" ]] || continue
    if [[ -x "$candidate/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc" && -d "$candidate/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk" ]]; then
      selected_developer_dir="$candidate"
      swiftc_binary="$candidate/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"
      macos_sdk="$candidate/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
      "$swiftc_binary" -swift-version 6 -version >/dev/null 2>&1 \
        || fail "Swift 6 is required; selected toolchain does not support -swift-version 6: $candidate"
      return
    fi
  done

  if candidate="$("$xcode_select" -p 2>/dev/null)"; then :; else candidate=""; fi
  [[ -n "$candidate" ]] || fail "no usable Xcode or Command Line Tools developer directory"
  if swiftc_binary="$(DEVELOPER_DIR="$candidate" "$xcrun_binary" --sdk macosx --find swiftc 2>/dev/null)"; then :; else swiftc_binary=""; fi
  if macos_sdk="$(DEVELOPER_DIR="$candidate" "$xcrun_binary" --sdk macosx --show-sdk-path 2>/dev/null)"; then :; else macos_sdk=""; fi
  [[ -n "$swiftc_binary" && -n "$macos_sdk" ]] || fail "could not resolve Swift and the macOS SDK from $candidate"
  selected_developer_dir="$candidate"
  [[ -x "$swiftc_binary" ]] || fail "Swift toolchain is not executable: $swiftc_binary"
  [[ -d "$macos_sdk" ]] || fail "macOS SDK is not available: $macos_sdk"
  "$swiftc_binary" -swift-version 6 -version >/dev/null 2>&1 \
    || fail "Swift 6 is required; selected toolchain does not support -swift-version 6: $candidate"
}

verify_app() {
  local app=$1
  local binary="$app/Contents/MacOS/$product_name"
  local verify_root
  local architectures

  [[ -d "$app" ]] || fail "app bundle not found: $app"
  require_file "$app/Contents/Info.plist"
  require_file "$binary"
  [[ -x "$binary" ]] || fail "main executable is not executable: $binary"
  [[ ! -d "$app/Contents/Frameworks" && ! -d "$app/Contents/PlugIns" && ! -d "$app/Contents/XPCServices" && ! -d "$app/Contents/Helpers" ]] || fail "nested code requires explicit signing before the outer app"

  "$plutil_binary" -lint "$app/Contents/Info.plist" >/dev/null
  require_plist_value "$app/Contents/Info.plist" CFBundleExecutable "$product_name"
  require_plist_value "$app/Contents/Info.plist" CFBundleIdentifier "$bundle_identifier"
  require_plist_value "$app/Contents/Info.plist" LSMinimumSystemVersion "$minimum_system_version"
  require_plist_value "$app/Contents/Info.plist" LSUIElement false
  [[ "$("$basename_binary" -- "$binary")" == "$product_name" ]] || fail "binary basename is not $product_name"

  architectures="$("$lipo_binary" -archs "$binary")"
  [[ "$architectures" == "arm64 x86_64" || "$architectures" == "x86_64 arm64" ]] || fail "expected exactly arm64 and x86_64, got: $architectures"

  verify_root="$("$mktemp_binary" -d "${task_prefix}verify.XXXXXXXX")" || fail "could not create verification directory"
  normalize_empty_dictionary "$entitlements" "$verify_root/source-entitlements.json"
  "$codesign_binary" -d --entitlements :- "$binary" > "$verify_root/actual-entitlements.plist"
  normalize_empty_dictionary "$verify_root/actual-entitlements.plist" "$verify_root/actual-entitlements.json"
  "$codesign_binary" -dvvv "$binary" > "$verify_root/signature.txt" 2>&1
  "$grep_binary" -Eq 'flags=.*runtime' "$verify_root/signature.txt" || fail "hardened runtime flag is absent from $binary"
  "$grep_binary" -Eq '^Signature=adhoc$' "$verify_root/signature.txt" || fail "signature is not ad-hoc: $binary"
  if "$grep_binary" -Eq '^Timestamp=' "$verify_root/signature.txt"; then
    fail "signature has a timestamp: $binary"
  fi

  "$codesign_binary" --verify --strict --verbose=2 "$binary"
  "$codesign_binary" --verify --strict --verbose=2 "$app"
  # This is verification only; signing is always explicit and never uses --deep.
  "$codesign_binary" --verify --deep --strict --verbose=2 "$app"
  assert_standalone_binary "$binary"
  validate_build_directory "$verify_root"
  "$rm_binary" -rf -- "$verify_root"
}

build_architecture() {
  local architecture=$1
  local triple="$architecture-apple-macosx$minimum_system_version"
  local module_root="$work_root/modules-$architecture"
  local library_root="$work_root/libraries-$architecture"
  local output="$work_root/$product_name-$architecture"
  local thin_architectures

  "$mkdir_binary" -p "$module_root" "$library_root"
  env \
    DEVELOPER_DIR="$selected_developer_dir" \
    SDKROOT="$macos_sdk" \
    TMPDIR="$work_root/tmp-$architecture" \
    CLANG_MODULE_CACHE_PATH="$work_root/clang-module-cache-$architecture" \
    SWIFT_MODULE_CACHE_PATH="$work_root/swift-module-cache-$architecture" \
    "$swiftc_binary" \
      -sdk "$macos_sdk" \
      -target "$triple" \
      -parse-as-library \
      -O \
      -whole-module-optimization \
      -warnings-as-errors \
      -strict-concurrency=complete \
      -swift-version 6 \
      -emit-library \
      -static \
      -emit-module \
      -module-name AgentjailApprovalCore \
      -emit-module-path "$module_root/AgentjailApprovalCore.swiftmodule" \
      -o "$library_root/libAgentjailApprovalCore.a" \
      "${core_sources[@]}"

  env \
    DEVELOPER_DIR="$selected_developer_dir" \
    SDKROOT="$macos_sdk" \
    TMPDIR="$work_root/tmp-$architecture" \
    CLANG_MODULE_CACHE_PATH="$work_root/clang-module-cache-$architecture" \
    SWIFT_MODULE_CACHE_PATH="$work_root/swift-module-cache-$architecture" \
    "$swiftc_binary" \
      -sdk "$macos_sdk" \
      -target "$triple" \
      -O \
      -whole-module-optimization \
      -warnings-as-errors \
      -strict-concurrency=complete \
      -swift-version 6 \
      -parse-as-library \
      -module-name AgentjailApprovalApp \
      -I "$module_root" \
      -L "$library_root" \
      -lAgentjailApprovalCore \
      -o "$output" \
      "${app_sources[@]}"

  [[ -x "$output" ]] || fail "release binary is not executable: $output"
  thin_architectures="$("$lipo_binary" -archs "$output")"
  [[ "$thin_architectures" == "$architecture" ]] || fail "expected a $architecture thin executable, got: $thin_architectures"
  assert_standalone_binary "$output"
}

if [[ "${1:-}" == "--verify-only" ]]; then
  (( $# == 2 )) || fail "usage: $0 --verify-only /path/to/AgentjailApproval.app"
  verify_app "$2"
  printf 'build-macos-approval-app: verified %s\n' "$2"
  exit 0
fi
(( $# == 0 )) || fail "usage: $0 [--verify-only /path/to/AgentjailApproval.app]"

artifact_root="$(resolve_artifact_root "$artifact_root")"
app_path="$artifact_root/$product_name.app"
work_root="$("$mktemp_binary" -d "$artifact_root/.build.XXXXXXXX")" || fail "could not create task build directory"
completed=0

cleanup() {
  local status=$?
  if [[ $completed -eq 1 ]]; then
    validate_build_directory "$work_root"
    "$rm_binary" -rf -- "$work_root"
  else
    printf 'build-macos-approval-app: preserved failed build directory at %s\n' "$work_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

require_file "$info_plist"
require_file "$entitlements"
[[ -d "$app_resources" && ! -L "$app_resources" ]] || fail "missing or symlinked approval app resources"
require_executable "$codesign_binary"
require_executable "$lipo_binary"
require_executable "$plutil_binary"
require_executable "$plist_buddy"
require_executable "$mktemp_binary"
require_executable "$find_binary"
require_executable "$sort_binary"
require_executable "$grep_binary"
require_executable "$tr_binary"
require_executable "$otool_binary"
require_executable "$shasum_binary"
require_executable "$awk_binary"
require_executable "$mkdir_binary"
require_executable "$cp_binary"
require_executable "$rm_binary"
require_executable "$mv_binary"
require_executable "$basename_binary"
require_executable "$xcode_select"
require_executable "$xcrun_binary"
resolve_toolchain
verify_package_manifest

core_sources=()
app_sources=()
while IFS= read -r source; do core_sources+=("$source"); done < <("$find_binary" "$package_root/Sources/AgentjailApprovalCore" -type f -name '*.swift' -print | LC_ALL=C "$sort_binary")
while IFS= read -r source; do app_sources+=("$source"); done < <("$find_binary" "$package_root/Sources/AgentjailApprovalApp" -type f -name '*.swift' -print | LC_ALL=C "$sort_binary")
(( ${#core_sources[@]} > 0 )) || fail "no approval Core Swift sources found"
(( ${#app_sources[@]} > 0 )) || fail "no approval App Swift sources found"

"$mkdir_binary" -p "$work_root/tmp-arm64" "$work_root/tmp-x86_64"
build_architecture arm64
build_architecture x86_64

stage_app="$work_root/$product_name.app"
"$mkdir_binary" -p "$stage_app/Contents/MacOS" "$stage_app/Contents/Resources"
"$lipo_binary" -create "$work_root/$product_name-arm64" "$work_root/$product_name-x86_64" -output "$stage_app/Contents/MacOS/$product_name"
"$cp_binary" "$info_plist" "$stage_app/Contents/Info.plist"
"$cp_binary" "$app_resources/agent-claude.svg" "$stage_app/Contents/Resources/agent-claude.svg"
"$cp_binary" "$app_resources/agent-codex.svg" "$stage_app/Contents/Resources/agent-codex.svg"
"$cp_binary" "$app_resources/agent-cursor.svg" "$stage_app/Contents/Resources/agent-cursor.svg"
"$cp_binary" "$app_resources/server-linear.svg" "$stage_app/Contents/Resources/server-linear.svg"

"$plutil_binary" -lint "$stage_app/Contents/Info.plist" >/dev/null
require_plist_value "$stage_app/Contents/Info.plist" CFBundleExecutable "$product_name"
[[ "$("$basename_binary" -- "$stage_app/Contents/MacOS/$product_name")" == "$product_name" ]] || fail "lipo output does not match CFBundleExecutable"

"$codesign_binary" --force --sign - --options runtime --timestamp=none --entitlements "$entitlements" "$stage_app"
verify_app "$stage_app"

if [[ -e "$app_path" || -L "$app_path" ]]; then
  [[ "$app_path" == "$artifact_root/$product_name.app" ]] || fail "refusing to replace an unexpected app path: $app_path"
  [[ ! -L "$app_path" ]] || fail "refusing to replace a symlinked app path: $app_path"
  "$rm_binary" -rf -- "$app_path"
fi
"$mv_binary" "$stage_app" "$app_path"
completed=1
printf 'build-macos-approval-app: app=%s\n' "$app_path"
