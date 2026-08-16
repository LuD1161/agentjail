#!/usr/bin/env bash
# Verify reproducible local assembly and DMG packaging for AgentJail Approval.
set -euo pipefail

readonly task_prefix="/private/tmp/agentjail-macos-approval-packaging."
readonly product_name="AgentjailApproval"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../../.." && pwd -P)"
build_script="$repo_root/scripts/build-macos-approval-app.sh"
package_script="$repo_root/scripts/package-macos-approval-dmg.sh"
entitlements="$repo_root/macos/AgentjailApproval/Resources/AgentjailApproval.entitlements"
detach_cleanup_test="$script_dir/detach_cleanup_test.sh"

fail() {
  printf 'macos approval packaging: %s\n' "$*" >&2
  exit 1
}

validate_task_root() {
  case "$1" in
    "$task_prefix"*) ;;
    *) fail "refusing to remove an invalid task root: $1" ;;
  esac
}

manifest() {
  local app=$1
  (
    cd -- "$app"
    find Contents -print | LC_ALL=C sort | while IFS= read -r path; do
      printf '%s|%s\n' "$path" "$(stat -f '%HT' "$path")"
    done
  )
}

normalized_plist() {
  /usr/bin/plutil -convert json -o - "$1" | tr -d '[:space:]'
}

first_root="$(mktemp -d "${task_prefix}first.XXXXXXXX")" || fail "could not create first artifact root"
second_root="$(mktemp -d "${task_prefix}second.XXXXXXXX")" || fail "could not create second artifact root"
outside_root="$(mktemp -d "${task_prefix}outside.XXXXXXXX")" || fail "could not create outside artifact root"
completed=0

cleanup() {
  local status=$?
  if [[ $completed -eq 1 ]]; then
    validate_task_root "$first_root"
    validate_task_root "$second_root"
    validate_task_root "$outside_root"
    rm -rf -- "$first_root" "$second_root" "$outside_root"
  else
    printf 'macos approval packaging: preserved artifacts at %s, %s, and %s\n' "$first_root" "$second_root" "$outside_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

[[ -x "$build_script" ]] || fail "missing executable build script: $build_script"
[[ -x "$package_script" ]] || fail "missing executable package script: $package_script"
[[ -x "$detach_cleanup_test" ]] || fail "missing executable detach cleanup test: $detach_cleanup_test"
"$detach_cleanup_test"
/usr/bin/plutil -lint "$entitlements" >/dev/null
[[ "$(normalized_plist "$entitlements")" == "{}" ]] || fail "source entitlements are not exactly empty"
cp "$repo_root/macos/AgentjailApproval/Package.swift" "$first_root/Package.swift"
sed -i '' 's/AgentjailApprovalCore/AgentjailApprovalCoreMutation/' "$first_root/Package.swift"
[[ "$(shasum -a 256 "$first_root/Package.swift" | awk '{print $1}')" != "388d7e67eae25baa948ad517133c425e934be8c16ceb7f627ee5a793651af801" ]] || fail "mutated manifest unexpectedly matches the reviewed package hash"

if APPROVAL_ARTIFACT_ROOT="$first_root/../escaped" "$build_script" > "$first_root/traversal.log" 2>&1; then
  fail "build script accepted a traversal artifact root"
fi
[[ ! -e "$(dirname -- "$first_root")/escaped" ]] || fail "build script created a traversal target"
ln -s "$outside_root" "$first_root/symlink-root"
if APPROVAL_ARTIFACT_ROOT="$first_root/symlink-root" "$build_script" > "$first_root/symlink.log" 2>&1; then
  fail "build script accepted a symlinked artifact root"
fi
if APPROVAL_ARTIFACT_ROOT="$first_root/../escaped" "$package_script" > "$first_root/dmg-traversal.log" 2>&1; then
  fail "DMG script accepted a traversal artifact root"
fi
grep -Fq '^Signature=adhoc$' "$build_script" || fail "build script does not attest ad-hoc signing"
grep -Fq '^Timestamp=' "$build_script" || fail "build script does not reject timestamps"

make -n macos-approval-app > "$first_root/make-app.txt"
make -n macos-approval-dmg > "$first_root/make-dmg.txt"
grep -Fqx './scripts/build-macos-approval-app.sh' "$first_root/make-app.txt" || fail "macos-approval-app does not invoke only its build script"
grep -Fqx './scripts/package-macos-approval-dmg.sh' "$first_root/make-dmg.txt" || fail "macos-approval-dmg does not invoke only its package script"

APPROVAL_ARTIFACT_ROOT="$first_root" "$build_script"
APPROVAL_ARTIFACT_ROOT="$second_root" "$build_script"

first_app="$first_root/$product_name.app"
second_app="$second_root/$product_name.app"
first_manifest="$first_root/contents-manifest.txt"
second_manifest="$second_root/contents-manifest.txt"
manifest "$first_app" > "$first_manifest"
manifest "$second_app" > "$second_manifest"
cmp -s "$first_manifest" "$second_manifest" || fail "app Contents manifests differ between builds"
cmp -s <(normalized_plist "$first_app/Contents/Info.plist") <(normalized_plist "$second_app/Contents/Info.plist") || fail "Info.plist differs between builds"

for app in "$first_app" "$second_app"; do
  binary="$app/Contents/MacOS/$product_name"
  architectures="$(lipo -archs "$binary")"
  [[ "$architectures" == "arm64 x86_64" || "$architectures" == "x86_64 arm64" ]] || fail "expected universal app, got: $architectures"
  /usr/bin/plutil -lint "$app/Contents/Info.plist" >/dev/null
  codesign --verify --strict --verbose=2 "$binary"
  codesign --verify --deep --strict --verbose=2 "$app"
  codesign -dvvv "$binary" > "$first_root/signature.txt" 2>&1
  grep -Fxq 'Signature=adhoc' "$first_root/signature.txt" || fail "signature is not ad-hoc"
  if grep -Eq '^Timestamp=' "$first_root/signature.txt"; then
    fail "ad-hoc package unexpectedly has a timestamp"
  fi
  if otool -L "$binary" | grep -E '^[[:space:]]' | grep -Eq 'AgentjailApprovalCore|/private/tmp/agentjail-macos-approval-'; then
    fail "executable has a Core or task-path dylib dependency"
  fi
  codesign -d --entitlements :- "$binary" > "$first_root/actual-entitlements.plist"
  [[ "$(normalized_plist "$first_root/actual-entitlements.plist")" == "{}" ]] || fail "signed entitlements are not exactly empty"
done

APPROVAL_ARTIFACT_ROOT="$first_root" "$package_script"
[[ -f "$first_root/$product_name.dmg" ]] || fail "DMG was not created"
hdiutil verify "$first_root/$product_name.dmg"
shasum -a 256 "$first_root/$product_name.dmg"

completed=1
printf 'macos approval packaging: PASS\n'
