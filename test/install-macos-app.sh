#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d /private/tmp/agentjail-install-macos-test.XXXXXXXX)"

cleanup() {
    case "$test_root" in
        /private/tmp/agentjail-install-macos-test.*) rm -rf -- "$test_root" ;;
        *) printf 'refusing to clean unexpected test root: %s\n' "$test_root" >&2 ;;
    esac
}
trap cleanup EXIT

fail() {
    printf 'install-macos-app-test: %s\n' "$*" >&2
    exit 1
}

fake_bin="$test_root/fake-bin"
source_app="$test_root/source/AgentJail.app"
applications="$test_root/Applications"
test_home="$test_root/home"
log="$test_root/actions.log"
mkdir -p "$fake_bin" "$source_app/Contents/Resources/bin" "$applications" "$test_home"
printf 'test dmg\n' > "$test_root/AgentJail.dmg"

cp "$repo_root/macos/AgentJail/Info.plist" "$source_app/Contents/Info.plist"
source_extension="$source_app/Contents/Library/SystemExtensions/com.blinkerlm.agentjail.extension.systemextension"
mkdir -p "$source_extension/Contents"
cp "$repo_root/macos/AgentjailExtension/Info.plist" "$source_extension/Contents/Info.plist"
for version_key in CFBundleShortVersionString CFBundleVersion; do
    version_value=$(plutil -extract "$version_key" raw "$source_app/Contents/Info.plist")
    plutil -replace "$version_key" -string "$version_value" "$source_extension/Contents/Info.plist"
done

cat > "$source_app/Contents/Resources/bin/agentjail" <<'EOF'
#!/bin/sh
printf 'agentjail %s\n' "$*" >> "$AGENTJAIL_TEST_LOG"
EOF
cat > "$source_app/Contents/Resources/bin/agentjail-hook" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 \
    "$source_app/Contents/Resources/bin/agentjail" \
    "$source_app/Contents/Resources/bin/agentjail-hook"

cat > "$fake_bin/hdiutil" <<'EOF'
#!/bin/sh
case "$1" in
    verify|detach) exit 0 ;;
    attach)
        shift
        mount_point=""
        while [ "$#" -gt 0 ]; do
            if [ "$1" = "-mountpoint" ]; then
                mount_point=$2
                shift 2
            else
                shift
            fi
        done
        cp -R "$AGENTJAIL_TEST_SOURCE_APP" "$mount_point/AgentJail.app"
        ;;
    *) exit 1 ;;
esac
EOF

cat > "$fake_bin/codesign" <<'EOF'
#!/bin/sh
for value in "$@"; do
    case "$value" in
        -R=*)
            printf '%s\n' "$value" >> "$AGENTJAIL_TEST_LOG"
            [ "${AGENTJAIL_TEST_WRONG_TEAM:-0}" != "1" ] || exit 1
            ;;
    esac
done
exit 0
EOF

cat > "$fake_bin/spctl" <<'EOF'
#!/bin/sh
for value in "$@"; do target=$value; done
if [ "${AGENTJAIL_TEST_FAIL_FINAL:-0}" = "1" ] && [ "$target" = "$AGENTJAIL_TEST_FINAL_APP" ]; then
    exit 1
fi
[ "${AGENTJAIL_TEST_GATEKEEPER_REJECT:-0}" != "1" ] || exit 1
if [ "${AGENTJAIL_TEST_NOT_NOTARIZED:-0}" = "1" ]; then
    echo 'source=Developer ID' >&2
else
    echo 'source=Notarized Developer ID' >&2
fi
exit 0
EOF

cat > "$fake_bin/open" <<'EOF'
#!/bin/sh
printf 'open %s\n' "$*" >> "$AGENTJAIL_TEST_LOG"
EOF
chmod 0755 "$fake_bin/hdiutil" "$fake_bin/codesign" "$fake_bin/spctl" "$fake_bin/open"

run_installer() {
    env \
        PATH="$fake_bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        HOME="$test_home" \
        SHELL=/bin/sh \
        AGENTJAIL_HOME="$test_home/.agentjail" \
        AGENTJAIL_ASSUME_YES=1 \
        AGENTJAIL_NO_MODIFY_PATH=1 \
        AGENTJAIL_TEST_APPLICATIONS_DIR="$applications" \
        AGENTJAIL_TEST_SOURCE_APP="$source_app" \
        AGENTJAIL_TEST_FINAL_APP="$applications/AgentJail.app" \
        AGENTJAIL_TEST_LOG="$log" \
        AGENTJAIL_VERSION=1.7.0 \
        LOCAL_MACOS_DMG="$test_root/AgentJail.dmg" \
        "$@" \
        /bin/sh "$repo_root/install.sh"
}

run_installer > "$test_root/success.out"

[ -d "$applications/AgentJail.app" ] || fail "app was not installed"
for expected_id in com.blinkerlm.agentjail com.blinkerlm.agentjail.extension; do
    grep -Fqx -- "-R=anchor apple generic and identifier \"$expected_id\" and certificate leaf[subject.OU] = \"Q98Z3744J2\"" "$log" \
        || fail "installer did not pin Apple signing identity for $expected_id"
done
[ -x "$test_home/.agentjail/bin/agentjail" ] || fail "CLI was not installed"
[ -x "$test_home/.agentjail/bin/agentjail-hook" ] || fail "hook was not installed"
for role in agentjail-daemon agentjail-shield agentjail-netproxy agentjail-secrets; do
    [ "$(readlink "$test_home/.agentjail/bin/$role")" = "agentjail" ] \
        || fail "$role is not a relative multicall symlink"
done
grep -Fqx 'agentjail install --yes' "$log" || fail "CLI setup was not run"
grep -Fqx "open $applications/AgentJail.app" "$log" || fail "app was not launched"
if find "$applications" -maxdepth 1 -name '.AgentJail.app.*' | grep . >/dev/null; then
    fail "successful install left staging paths"
fi

rm -rf -- "$applications/AgentJail.app" "$test_home/.agentjail"
mkdir -p "$applications/AgentJail.app"
printf 'previous app\n' > "$applications/AgentJail.app/previous.txt"
: > "$log"

if run_installer AGENTJAIL_TEST_FAIL_FINAL=1 > "$test_root/rollback.out" 2>&1; then
    fail "post-install Gatekeeper failure unexpectedly succeeded"
fi
[ -f "$applications/AgentJail.app/previous.txt" ] || fail "failed upgrade did not restore previous app"
if find "$applications" -maxdepth 1 -name '.AgentJail.app.*' | grep . >/dev/null; then
    fail "failed upgrade left staging paths"
fi

rm -rf -- "$applications/AgentJail.app"
if run_installer AGENTJAIL_TEST_FAIL_FINAL=1 > "$test_root/clean-failure.out" 2>&1; then
    fail "failed clean install unexpectedly succeeded"
fi
[ ! -e "$applications/AgentJail.app" ] || fail "failed clean install left an unverified app"
if find "$applications" -maxdepth 1 -name '.AgentJail.app.*' | grep . >/dev/null; then
    fail "failed clean install left staging paths"
fi

# Rejected payloads must not replace an existing app or execute its CLI.
mkdir -p "$applications/AgentJail.app"
printf 'previous app\n' > "$applications/AgentJail.app/previous.txt"
assert_rejected() {
    : > "$log"
    if run_installer "$@" > "$test_root/rejected.out" 2>&1; then
        fail "invalid distribution unexpectedly installed: $*"
    fi
    [ -f "$applications/AgentJail.app/previous.txt" ] || fail "rejection replaced previous app"
    if grep -E '^(agentjail|open) ' "$log" >/dev/null; then
        fail "rejection executed payload"
    fi
}
assert_rejected AGENTJAIL_TEST_WRONG_TEAM=1
assert_rejected AGENTJAIL_TEST_NOT_NOTARIZED=1
assert_rejected AGENTJAIL_TEST_GATEKEEPER_REJECT=1
plutil -replace CFBundleIdentifier -string com.example.wrong "$source_extension/Contents/Info.plist"
assert_rejected
plutil -replace CFBundleIdentifier -string com.blinkerlm.agentjail.extension "$source_extension/Contents/Info.plist"
plutil -replace CFBundleVersion -string 999999 "$source_extension/Contents/Info.plist"
assert_rejected
rm -rf -- "$source_extension"
assert_rejected

printf 'install-macos-app-test: ok\n'
