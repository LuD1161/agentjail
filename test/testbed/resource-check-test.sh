#!/usr/bin/env bash
set -euo pipefail

TESTBED_DRIVER=lima
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

pass=0
fail=0
result_file="$(mktemp "${TMPDIR:-/tmp}/agentjail-resource-test.XXXXXX")"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentjail-lifecycle-test.XXXXXX")"
trap 'rm -f "$result_file"; rm -rf "$fixture_dir"' EXIT

check_pass() {
    local name="$1"; shift
    if "$@" >"$result_file" 2>&1; then
        echo "PASS $name"
        pass=$((pass + 1))
    else
        echo "FAIL $name"
        sed 's/^/    /' "$result_file"
        fail=$((fail + 1))
    fi
}

check_fail() {
    local name="$1" pattern="$2"; shift 2
    if "$@" >"$result_file" 2>&1; then
        echo "FAIL $name (unexpected success)"
        fail=$((fail + 1))
    elif grep -q "$pattern" "$result_file"; then
        echo "PASS $name"
        pass=$((pass + 1))
    else
        echo "FAIL $name (missing '$pattern')"
        sed 's/^/    /' "$result_file"
        fail=$((fail + 1))
    fi
}

with_resources() {
    local memory_gib="$1" disk_gib="$2" allocation="$3"
    (
        host_available_memory_bytes() { gib_bytes "$memory_gib"; }
        host_available_disk_bytes() { gib_bytes "$disk_gib"; }
        testbed_storage_dir() { echo /testbed-storage; }
        assert_host_resources fixture "$allocation"
    )
}

check_pass "new VM fits RAM and disk" with_resources 8 30 create
check_pass "reused VM needs only disk reserve" with_resources 8 6 reuse
check_fail "low RAM refuses before boot" "insufficient host RAM" with_resources 5 30 create
check_fail "low disk refuses new VM" "insufficient host disk" with_resources 8 24 create
check_fail "low disk refuses reused VM" "insufficient host disk" with_resources 8 4 reuse

darwin_vm_stat_is_parsed() {
    local actual
    actual="$(darwin_available_memory_bytes <<'EOF'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               1000.
Pages active:                             9000.
Pages inactive:                           2000.
Pages speculative:                         500.
Pages wired down:                         1000.
Pages purgeable:                           500.
EOF
)"
    [ "$actual" -eq $((3500 * 16384)) ]
}

check_pass "macOS reclaimable memory is parsed" darwin_vm_stat_is_parsed

fake_bin="$fixture_dir/bin"
mkdir -p "$fake_bin" "$fixture_dir/home" "$fixture_dir/lima"

cat >"$fake_bin/limactl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$FAKE_LIMACTL_LOG"
case "${1:-}" in
    list)
        [ -f "$FAKE_LIMACTL_STATE" ] && echo tb-fixture
        ;;
    start)
        [ "${FAKE_START_FAIL:-0}" = 0 ] || exit 23
        touch "$FAKE_LIMACTL_STATE"
        ;;
    stop|snapshot) ;;
    delete) rm -f "$FAKE_LIMACTL_STATE" ;;
    shell) echo x86_64 ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$fake_bin/limactl"

cat >"$fake_bin/make" <<'EOF'
#!/usr/bin/env bash
exit 42
EOF
chmod +x "$fake_bin/make"

run_harness() {
    local start_fail="$1" keep_vm="$2"; shift 2
    : >"$fixture_dir/limactl.log"
    rm -f "$fixture_dir/lima.state"
    PATH="$fake_bin:$PATH" \
    HOME="$fixture_dir/home" \
    LIMA_HOME="$fixture_dir/lima" \
    FAKE_LIMACTL_LOG="$fixture_dir/limactl.log" \
    FAKE_LIMACTL_STATE="$fixture_dir/lima.state" \
    FAKE_START_FAIL="$start_fail" \
    AGENTJAIL_TESTBED_KEEP_VM="$keep_vm" \
    AGENTJAIL_TESTBED_REQUIRED_MEMORY_GIB=1 \
    AGENTJAIL_TESTBED_REQUIRED_DISK_GIB=1 \
    AGENTJAIL_TESTBED_HOST_MEMORY_RESERVE_GIB=1 \
    AGENTJAIL_TESTBED_HOST_DISK_RESERVE_GIB=1 \
        bash "$TESTBED_DIR/testbed.sh" "$@"
}

partial_create_is_removed() {
    ! run_harness 1 0 create fixture
    grep -q '^start ' "$fixture_dir/limactl.log"
    grep -q '^delete ' "$fixture_dir/limactl.log"
    [ ! -e "$fixture_dir/lima.state" ]
}

failed_gate_is_destroyed() {
    ! run_harness 0 0 gate --scenario e2e-smoke
    grep -q '^delete ' "$fixture_dir/limactl.log"
    [ ! -e "$fixture_dir/lima.state" ]
}

retained_gate_is_stopped() {
    ! run_harness 0 1 gate --scenario e2e-smoke
    grep -q '^stop ' "$fixture_dir/limactl.log"
    ! grep -q '^delete ' "$fixture_dir/limactl.log"
    [ -e "$fixture_dir/lima.state" ]
}

check_pass "partial VM creation is removed" partial_create_is_removed
check_pass "failed gate releases RAM and disk" failed_gate_is_destroyed
check_pass "retained gate is stopped" retained_gate_is_stopped

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
