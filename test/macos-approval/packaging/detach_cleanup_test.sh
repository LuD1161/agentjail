#!/usr/bin/env bash
# Exercise package cleanup against deterministic hdiutil and mount fakes.
set -euo pipefail

readonly task_prefix="/private/tmp/agentjail-macos-approval-detach-test."

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../../.." && pwd -P)"
source_script="$repo_root/scripts/package-macos-approval-dmg.sh"

fail() {
  printf 'macos approval detach cleanup: %s\n' "$*" >&2
  exit 1
}

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || {
  printf 'macos approval detach cleanup: SKIP (requires macOS packaging tools)\n'
  exit 0
}

test_root="$(/usr/bin/mktemp -d "${task_prefix}XXXXXXXX")" || fail "could not create test root"

cleanup() {
  local status=$?
  if [[ -d "$test_root" && ! -L "$test_root" ]]; then
    case "$test_root" in
      "$task_prefix"*) /bin/rm -rf -- "$test_root" ;;
      *) fail "refusing to remove an invalid test root: $test_root" ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT

write_fake_hdiutil() {
  local path=$1
  /bin/cp /dev/null "$path"
  /bin/chmod 700 "$path"
  /usr/bin/tee "$path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "$1" in
  create) : > "${!#}" ;;
  verify) ;;
  attach)
    mount_point=""
    shift
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -mountpoint) mount_point=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    [[ -n "$mount_point" ]] || exit 64
    printf '%s\n' "$mount_point" > "$FAKE_STATE_ROOT/mount-point"
    /bin/mkdir -p "$mount_point/AgentjailApproval.app"
    /bin/ln -s /Applications "$mount_point/Applications"
    if [[ "${FAKE_SIGNAL_ON_ATTACH:-0}" == "1" ]]; then
      /bin/kill -TERM "$PPID"
    fi
    exit "${FAKE_ATTACH_STATUS:-0}"
    ;;
  detach)
    printf '%s\n' "$2" >> "$FAKE_STATE_ROOT/detach.log"
    exit "${FAKE_DETACH_STATUS:-0}"
    ;;
  *) exit 64 ;;
esac
EOF
}

write_fake_mount() {
  local path=$1
  /bin/cp /dev/null "$path"
  /bin/chmod 700 "$path"
  /usr/bin/tee "$path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

mount_point="$(/bin/cat "$FAKE_STATE_ROOT/mount-point")"
case "$FAKE_MOUNT_STATE" in
  active) printf '/dev/disk99 on %s (hfs, local, read-only)\n' "$mount_point" ;;
  absent) ;;
  error) exit 1 ;;
  *) exit 64 ;;
esac
EOF
}

write_fake_build() {
  local path=$1
  /bin/cp /dev/null "$path"
  /bin/chmod 700 "$path"
  /usr/bin/tee "$path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--verify-only" ]]; then
  [[ -d "${2:-}" ]] || exit 1
  exit 0
fi
/bin/mkdir -p "$APPROVAL_ARTIFACT_ROOT/AgentjailApproval.app"
EOF
}

write_fake_rm() {
  local path=$1
  /bin/cp /dev/null "$path"
  /bin/chmod 700 "$path"
  /usr/bin/tee "$path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "$FAKE_RM_LOG"
exec /bin/rm "$@"
EOF
}

run_case() {
  local name=$1
  local mount_state=$2
  local expect_status=$3
  local signal_on_attach=${4:-0}
  local attach_status=${5:-0}
  local case_root="$test_root/$name"
  local fake_bin="$case_root/fake-bin"
  local fake_repo="$case_root/repo"
  local artifact_root="$case_root/artifacts"
  local state_root="$case_root/state"
  local fake_rm="$fake_bin/rm"
  local package_script="$fake_repo/scripts/package-macos-approval-dmg.sh"
  local output="$case_root/output.log"
  local status
  local expected_stage_root
  local stage_roots=()

  /bin/mkdir -p "$fake_bin" "$fake_repo/scripts" "$artifact_root" "$state_root"
  write_fake_hdiutil "$fake_bin/hdiutil"
  write_fake_mount "$fake_bin/mount"
  write_fake_build "$fake_repo/scripts/build-macos-approval-app.sh"
  write_fake_rm "$fake_rm"
  : > "$state_root/rm.log"
  /usr/bin/sed "s|readonly rm_binary=\"/bin/rm\"|readonly rm_binary=\"$fake_rm\"|" "$source_script" > "$package_script"
  /bin/chmod 700 "$package_script"

  set +e
  APPROVAL_ARTIFACT_ROOT="$artifact_root" \
    APPROVAL_HDIUTIL_BINARY="$fake_bin/hdiutil" \
    APPROVAL_MOUNT_BINARY="$fake_bin/mount" \
    FAKE_STATE_ROOT="$state_root" \
    FAKE_RM_LOG="$state_root/rm.log" \
    FAKE_MOUNT_STATE="$mount_state" \
    FAKE_SIGNAL_ON_ATTACH="$signal_on_attach" \
    FAKE_ATTACH_STATUS="$attach_status" \
    "$package_script" >"$output" 2>&1
  status=$?
  set -e

  expected_stage_root="$(/usr/bin/dirname "$(/bin/cat "$state_root/mount-point")")"

  shopt -s nullglob
  stage_roots=("$artifact_root"/.dmg-stage.*)
  shopt -u nullglob
  if [[ "$expect_status" == "success" ]]; then
    [[ $status -eq 0 ]] || fail "$name exited $status, want success"
    [[ ${#stage_roots[@]} -eq 0 ]] || fail "$name retained a confirmed-detached stage root"
    /usr/bin/grep -Fxq -- "-rf -- $expected_stage_root" "$state_root/rm.log" || fail "$name did not remove exactly the confirmed-detached stage root"
  else
    [[ $status -ne 0 ]] || fail "$name unexpectedly succeeded"
    [[ ${#stage_roots[@]} -eq 1 && -d "${stage_roots[0]}" ]] || fail "$name did not preserve its stage root"
    [[ "${stage_roots[0]}" == "$expected_stage_root" ]] || fail "$name preserved an unexpected stage root"
    /usr/bin/grep -Fq -- 'could not confirm' "$output" || fail "$name did not report failed detach confirmation"
    [[ -s "$state_root/detach.log" ]] || fail "$name did not attempt cleanup detach"
    if /usr/bin/grep -Fq -- "${stage_roots[0]}" "$state_root/rm.log"; then
      fail "$name recursively removed a stage root with an active or indeterminate mount"
    fi
  fi
}

run_case detach-success-still-mounted active failure
run_case detach-success-query-error error failure
run_case detach-success-confirmed-absent absent success
run_case signal-cleanup-still-mounted active failure 1
run_case attach-nonzero-still-mounted active failure 0 1
run_case attach-nonzero-query-error error failure 0 1

printf 'macos approval detach cleanup: PASS\n'
