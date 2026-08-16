#!/usr/bin/env bash
# Package the standalone AgentJail Approval app into a local-only DMG.
set -euo pipefail

readonly product_name="AgentjailApproval"
readonly task_prefix="/private/tmp/agentjail-macos-approval-"
readonly hdiutil_binary="${APPROVAL_HDIUTIL_BINARY:-/usr/bin/hdiutil}"
readonly mount_binary="${APPROVAL_MOUNT_BINARY:-/sbin/mount}"
readonly ditto_binary="/usr/bin/ditto"
readonly shasum_binary="/usr/bin/shasum"
readonly readlink_binary="/usr/bin/readlink"
readonly awk_binary="/usr/bin/awk"
readonly mkdir_binary="/bin/mkdir"
readonly rm_binary="/bin/rm"
readonly ln_binary="/bin/ln"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
default_artifact_root="$repo_root/build/macos-approval"
default_build_root="$repo_root/build"
artifact_root="${APPROVAL_ARTIFACT_ROOT:-$default_artifact_root}"
build_script="$script_dir/build-macos-approval-app.sh"

fail() {
  printf 'package-macos-approval-dmg: %s\n' "$*" >&2
  exit 1
}

validate_artifact_root() {
  [[ "$1" == /* ]] || fail "artifact root must be absolute: $1"
  case "/$1/" in
    */../*) fail "artifact root must not contain a parent traversal: $1" ;;
  esac
  case "$1" in
    "$default_artifact_root")
      [[ ! -e "$default_build_root" || ( -d "$default_build_root" && ! -L "$default_build_root" ) ]] || fail "build root must be a non-symlink directory: $default_build_root"
      "$mkdir_binary" -p -- "$default_build_root"
      [[ "$(cd -P -- "$default_build_root" && pwd -P)" == "$default_build_root" ]] || fail "build root escapes the repository: $default_build_root"
      [[ ! -e "$default_artifact_root" || ( -d "$default_artifact_root" && ! -L "$default_artifact_root" ) ]] || fail "approval artifact root must be a non-symlink directory: $default_artifact_root"
      "$mkdir_binary" -p -- "$default_artifact_root"
      ;;
    "$task_prefix"*)
      [[ -d "$1" && ! -L "$1" ]] || fail "task artifact root must be an existing non-symlink directory: $1"
      ;;
    *) fail "artifact root must be $default_artifact_root or an existing $task_prefix* directory: $1" ;;
  esac
  canonical_artifact_root="$(cd -P -- "$1" && pwd -P)"
  case "$canonical_artifact_root" in
    "$default_artifact_root"|"$task_prefix"*) ;;
    *) fail "artifact root escapes its allowed boundary: $1" ;;
  esac
}

validate_dmg_path() {
  [[ "$1" == "$artifact_root/$product_name.dmg" ]] || fail "DMG path must be $artifact_root/$product_name.dmg"
  [[ ! -L "$1" ]] || fail "refusing to overwrite a symlinked DMG path: $1"
}

validate_stage_root() {
  case "$1" in
    "$artifact_root"/.dmg-stage.*) ;;
    *) fail "refusing to remove an invalid DMG staging directory: $1" ;;
  esac
  [[ ! -L "$1" ]] || fail "refusing to remove a symlinked DMG staging directory: $1"
  [[ "$(cd -P -- "$1" && pwd -P)" == "$1" ]] || fail "DMG staging directory escapes its allowed boundary: $1"
}

validate_artifact_root "$artifact_root"
artifact_root="$canonical_artifact_root"
app_path="${APPROVAL_APP_PATH:-$artifact_root/$product_name.app}"
dmg_path="${APPROVAL_DMG_PATH:-$artifact_root/$product_name.dmg}"
validate_dmg_path "$dmg_path"

[[ -x "$build_script" ]] || fail "build script is not executable: $build_script"
[[ -x "$hdiutil_binary" ]] || fail "missing required executable: $hdiutil_binary"
[[ -x "$mount_binary" ]] || fail "missing required executable: $mount_binary"
[[ -x "$ditto_binary" ]] || fail "missing required executable: $ditto_binary"
[[ -x "$shasum_binary" ]] || fail "missing required executable: $shasum_binary"
[[ -x "$readlink_binary" ]] || fail "missing required executable: $readlink_binary"
[[ -x "$awk_binary" ]] || fail "missing required executable: $awk_binary"
[[ -x "$mkdir_binary" ]] || fail "missing required executable: $mkdir_binary"
[[ -x "$rm_binary" ]] || fail "missing required executable: $rm_binary"
[[ -x "$ln_binary" ]] || fail "missing required executable: $ln_binary"
if [[ ! -d "$app_path" ]]; then
  [[ "$app_path" == "$artifact_root/$product_name.app" ]] || fail "refusing to build an app at a custom path: $app_path"
  APPROVAL_ARTIFACT_ROOT="$artifact_root" "$build_script"
fi
"$build_script" --verify-only "$app_path"

stage_root="$(mktemp -d "$artifact_root/.dmg-stage.XXXXXXXX")" || fail "could not create DMG staging directory"
mount_point="$stage_root/mount"
attached=0
completed=0

mount_state() {
  local mount_output

  if ! mount_output="$("$mount_binary" 2>/dev/null)"; then
    return 2
  fi
  if [[ "$mount_output" == *"on $mount_point "* ]]; then
    return 0
  fi
  return 1
}

detach_and_confirm() {
  local state

  if ! "$hdiutil_binary" detach "$mount_point"; then
    return 1
  fi
  state=0
  mount_state || state=$?
  case "$state" in
    0) return 2 ;;
    1) attached=0 ;;
    *) return 3 ;;
  esac
}

cleanup() {
  local status=$?
  local detach_status
  if [[ $attached -eq 1 ]]; then
    set +e
    detach_and_confirm
    detach_status=$?
    set -e
    if [[ $detach_status -ne 0 ]]; then
      printf 'package-macos-approval-dmg: could not confirm %s is detached; preserving %s\n' "$mount_point" "$stage_root" >&2
      exit 1
    fi
  fi
  if [[ $completed -eq 1 ]]; then
    validate_stage_root "$stage_root"
    "$rm_binary" -rf -- "$stage_root"
  else
    printf 'package-macos-approval-dmg: preserved failed staging directory at %s\n' "$stage_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

"$ditto_binary" "$app_path" "$stage_root/$product_name.app"
"$ln_binary" -s /Applications "$stage_root/Applications"

"$hdiutil_binary" create \
  -volname "AgentJail Approval" \
  -srcfolder "$stage_root" \
  -format UDZO \
  -fs HFS+ \
  -ov \
  "$dmg_path"
"$hdiutil_binary" verify "$dmg_path"
# shellcheck disable=SC2016
checksum="$("$shasum_binary" -a 256 "$dmg_path" | "$awk_binary" '{print $1}')"
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || fail "invalid SHA-256 output for $dmg_path"

"$mkdir_binary" "$mount_point"
attached=1
if ! "$hdiutil_binary" attach -readonly -nobrowse -mountpoint "$mount_point" "$dmg_path" >/dev/null; then
  fail "could not attach $dmg_path"
fi
[[ -d "$mount_point/$product_name.app" ]] || fail "mounted DMG does not contain $product_name.app"
[[ -L "$mount_point/Applications" ]] || fail "mounted DMG does not contain an Applications symlink"
[[ "$("$readlink_binary" "$mount_point/Applications")" == "/Applications" ]] || fail "Applications link does not target /Applications"
"$build_script" --verify-only "$mount_point/$product_name.app"
if ! detach_and_confirm; then
  fail "could not confirm $mount_point is detached"
fi

completed=1
printf 'package-macos-approval-dmg: dmg=%s\n' "$dmg_path"
printf 'package-macos-approval-dmg: sha256=%s\n' "$checksum"
