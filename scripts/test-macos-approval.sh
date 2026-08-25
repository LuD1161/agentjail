#!/usr/bin/env bash
# Runs the macOS approval XCTest suites without SwiftPM build artifacts.
set -euo pipefail

readonly task_prefix="/private/tmp/agentjail-macos-approval-tests-032."

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
package_root="$repo_root/macos/AgentjailApproval"
xcode_root="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
swiftc="$xcode_root/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"
sdk="$xcode_root/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
xcode_library_dir="$xcode_root/Platforms/MacOSX.platform/Developer/usr/lib"
xcode_framework_dir="$xcode_root/Platforms/MacOSX.platform/Developer/Library/Frameworks"
xctest="$xcode_root/usr/bin/xctest"
keep_artifacts=0
completed=0

fail() {
  printf 'test-macos-approval: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -e "$1" ]] || fail "missing required path: $1"
}

if [[ "${1:-}" == "--keep-artifacts" ]]; then
  keep_artifacts=1
  shift
fi
(( $# == 0 )) || fail "usage: $0 [--keep-artifacts]"

artifact_root="$(mktemp -d "${task_prefix}XXXXXXXX")" || fail "could not create artifact root"

validate_artifact_root() {
  local suffix="${artifact_root#"$task_prefix"}"
  case "$artifact_root" in
    "${task_prefix}"[[:alnum:]]*) [[ -n "$suffix" && "$suffix" != */* ]] ;;
    *) fail "refusing to remove an invalid artifact root: $artifact_root" ;;
  esac
}

cleanup() {
  local status=$?
  if [[ $status -eq 0 && $completed -eq 1 && "$keep_artifacts" != "1" ]]; then
    validate_artifact_root
    rm -rf -- "$artifact_root"
    printf 'test-macos-approval: cleaned %s\n' "$artifact_root"
  else
    printf 'test-macos-approval: preserved artifacts at %s\n' "$artifact_root" >&2
  fi
}
trap cleanup EXIT

require_file "$swiftc"
require_file "$sdk"
require_file "$xcode_library_dir/XCTest.swiftmodule"
require_file "$xcode_framework_dir/XCTest.framework"
require_file "$xctest"
require_file "$package_root"

mkdir -p \
  "$artifact_root/clang-module-cache" \
  "$artifact_root/swift-module-cache" \
  "$artifact_root/lib" \
  "$artifact_root/modules" \
  "$artifact_root/tests" \
  "$artifact_root/typecheck"

discover_sources() {
  find "$1" -type f -name '*.swift' -print | LC_ALL=C sort
}

core_sources=()
app_sources=()
core_test_sources=()
app_test_sources=()
while IFS= read -r source; do core_sources+=("$source"); done < <(discover_sources "$package_root/Sources/AgentjailApprovalCore")
while IFS= read -r source; do app_sources+=("$source"); done < <(discover_sources "$package_root/Sources/AgentjailApprovalApp")
while IFS= read -r source; do core_test_sources+=("$source"); done < <(discover_sources "$package_root/Tests/AgentjailApprovalCoreTests")
while IFS= read -r source; do app_test_sources+=("$source"); done < <(discover_sources "$package_root/Tests/AgentjailApprovalAppTests")

(( ${#core_sources[@]} > 0 )) || fail "no core sources discovered"
(( ${#app_sources[@]} > 0 )) || fail "no app sources discovered"
(( ${#core_test_sources[@]} > 0 )) || fail "no core XCTest sources discovered"
(( ${#app_test_sources[@]} > 0 )) || fail "no app XCTest sources discovered"

swift_env=(
  env
  "TMPDIR=/tmp"
  "CLANG_MODULE_CACHE_PATH=$artifact_root/clang-module-cache"
  "SWIFT_MODULE_CACHE_PATH=$artifact_root/swift-module-cache"
)

compile_production_modules() {
  "${swift_env[@]}" "$swiftc" \
    -sdk "$sdk" \
    -target arm64-apple-macosx13.0 \
    -parse-as-library \
    -emit-library -emit-module -enable-testing \
    -module-name AgentjailApprovalCore \
    -emit-module-path "$artifact_root/modules/AgentjailApprovalCore.swiftmodule" \
    -o "$artifact_root/lib/libAgentjailApprovalCore.dylib" \
    "${core_sources[@]}"

  "${swift_env[@]}" "$swiftc" \
    -sdk "$sdk" \
    -target arm64-apple-macosx13.0 \
    -parse-as-library \
    -emit-library -emit-module -enable-testing \
    -module-name AgentjailApprovalApp \
    -I "$artifact_root/modules" \
    -L "$artifact_root/lib" -lAgentjailApprovalCore \
    -Xlinker -rpath -Xlinker "$artifact_root/lib" \
    -emit-module-path "$artifact_root/modules/AgentjailApprovalApp.swiftmodule" \
    -o "$artifact_root/lib/libAgentjailApprovalApp.dylib" \
    "${app_sources[@]}"
}

make_test_bundle() {
  local bundle_name=$1
  local bundle_path="$artifact_root/tests/$bundle_name.xctest"
  local info_plist="$bundle_path/Contents/Info.plist"

  mkdir -p "$bundle_path/Contents/MacOS"
  /usr/bin/plutil -create xml1 "$info_plist"
  /usr/bin/plutil -insert CFBundleExecutable -string "$bundle_name" "$info_plist"
  /usr/bin/plutil -insert CFBundleIdentifier -string "com.blinkerlm.agentjail.approval.manual.$bundle_name" "$info_plist"
  /usr/bin/plutil -insert CFBundlePackageType -string BNDL "$info_plist"
  printf '%s\n' "$bundle_path"
}

compile_test_bundle() {
  local bundle_name=$1
  local module_name=$2
  local bundle_path
  local test_sources=()
  local link_args=(
    -I "$artifact_root/modules"
    -L "$artifact_root/lib"
    -lAgentjailApprovalCore
  )

  if [[ "$module_name" == "AgentjailApprovalAppTests" ]]; then
    test_sources=("${app_test_sources[@]}")
    link_args+=( -lAgentjailApprovalApp )
  else
    test_sources=("${core_test_sources[@]}")
  fi

  bundle_path="$(make_test_bundle "$bundle_name")"
  "${swift_env[@]}" "$swiftc" \
    -sdk "$sdk" \
    -target arm64-apple-macosx14.0 \
    -parse-as-library \
    -emit-library -enable-testing \
    -module-name "$module_name" \
    "${link_args[@]}" \
    -I "$xcode_library_dir" \
    -F "$xcode_framework_dir" -framework XCTest \
    -L "$xcode_library_dir" -lXCTestSwiftSupport \
    -Xlinker -rpath -Xlinker "$artifact_root/lib" \
    -Xlinker -rpath -Xlinker "$xcode_framework_dir" \
    -Xlinker -rpath -Xlinker "$xcode_library_dir" \
    -o "$bundle_path/Contents/MacOS/$bundle_name" \
    "${test_sources[@]}"

  "$xctest" "$bundle_path"
}

typecheck_production_sources() {
  local architecture
  local typecheck_dir
  for architecture in arm64 x86_64; do
    typecheck_dir="$artifact_root/typecheck/$architecture"
    mkdir -p "$typecheck_dir"
    "${swift_env[@]}" "$swiftc" \
      -sdk "$sdk" \
      -target "$architecture-apple-macosx13.0" \
      -parse-as-library \
      -emit-module \
      -module-name AgentjailApprovalCore \
      -emit-module-path "$typecheck_dir/AgentjailApprovalCore.swiftmodule" \
      "${core_sources[@]}"
    "${swift_env[@]}" "$swiftc" \
      -sdk "$sdk" \
      -target "$architecture-apple-macosx13.0" \
      -parse-as-library \
      -I "$typecheck_dir" \
      -typecheck \
      "${app_sources[@]}"
  done
}

compile_production_modules
compile_test_bundle AgentjailApprovalCoreTests AgentjailApprovalCoreTests
compile_test_bundle AgentjailApprovalAppTests AgentjailApprovalAppTests
typecheck_production_sources

completed=1
printf 'test-macos-approval: all discovered XCTest suites passed\n'
