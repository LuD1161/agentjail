#!/bin/sh
# install.sh — agentjail one-liner installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/LuD1161/agentjail/main/install.sh | sh
#
# Environment overrides:
#   AGENTJAIL_VERSION     — pin to a specific tag (default: latest)
#   AGENTJAIL_HOME        — installation root (default: $HOME/.agentjail)
#   AGENTJAIL_DRY_RUN     — set to 1 to skip actual install; verify download, signature, and checksum only
#   LOCAL_TARBALL         — trusted local development tarball; skips release authentication
#
# POSIX sh — no bash-isms; passes shellcheck.
set -eu

REPO="LuD1161/agentjail"
VERSION="${AGENTJAIL_VERSION:-latest}"
INSTALL_DIR="${AGENTJAIL_HOME:-$HOME/.agentjail}/bin"
DRY_RUN="${AGENTJAIL_DRY_RUN:-0}"
# Must match release.yml and the updater's release key. See ADR 0145-install-signature-trust.
SIGNING_PUBLIC_KEY='RWRg/Bbl+U571C1qv/08AwUwlvf6zG4lYzV8e0QHFd0FrjYTmImUoRpQ'

if [ -z "${LOCAL_TARBALL:-}" ] && ! command -v minisign >/dev/null 2>&1; then
    echo "agentjail installer: minisign is required to authenticate release downloads." >&2
    echo "  Install minisign through your trusted package manager, then retry." >&2
    echo "  macOS: brew install minisign; Debian/Ubuntu: sudo apt-get install minisign" >&2
    echo "  No downloaded binaries have been executed or installed." >&2
    exit 7
fi

# Network work has bounded retries and deadlines; no download can wait forever.
fetch() {
    curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 240 "$@"
}

# --- Detect OS + arch ---

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    arm64|aarch64) ARCH=arm64 ;;
    x86_64|amd64)  ARCH=amd64 ;;
    *) echo "agentjail installer: unsupported arch: $ARCH" >&2; exit 2 ;;
esac

case "$OS" in
    darwin|linux) : ;;
    *) echo "agentjail installer: unsupported OS: $OS" >&2; exit 2 ;;
esac

PLATFORM="${OS}-${ARCH}"
printf '\n📦  agentjail installer  ·  %s\n\n' "${PLATFORM}"

# Resolve a SHA-256 command once, at top level, so a missing hasher fails
# closed HERE (exit terminates the script) rather than inside a pipeline,
# where POSIX sh would swallow the helper's exit status.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_CMD="shasum -a 256"
else
    echo "agentjail installer: no SHA-256 tool found (need sha256sum or shasum)." >&2
    echo "  Install GNU coreutils (Linux) or perl-Digest-SHA, then retry." >&2
    exit 6
fi

# sha256: portable SHA-256 dispatcher. Output format "<hash>  <file>" (two
# spaces) is identical for sha256sum and shasum -a 256, which install.sh relies on.
sha256() {
    # shellcheck disable=SC2086  # SHA256_CMD intentionally word-splits (e.g. "shasum -a 256")
    $SHA256_CMD "$@"
}

# _spin_frame prints the spinner glyph for tick $1. Frames are emitted by a
# case statement (not string slicing) so multibyte braille glyphs stay intact
# across POSIX sh implementations. $2=1 selects UTF-8 braille; otherwise ASCII.
_spin_frame() {
    if [ "$2" = "1" ]; then
        case "$1" in
            0) printf '⠋' ;; 1) printf '⠙' ;; 2) printf '⠹' ;; 3) printf '⠸' ;;
            4) printf '⠼' ;; 5) printf '⠴' ;; 6) printf '⠦' ;; 7) printf '⠧' ;;
            8) printf '⠇' ;; *) printf '⠏' ;;
        esac
    else
        # shellcheck disable=SC1003  # '\' is a literal backslash frame, not an escape
        case $(( $1 % 4 )) in
            0) printf '|' ;; 1) printf '/' ;; 2) printf '-' ;; *) printf '\\' ;;
        esac
    fi
}

# spin runs "$@" (after the label) while animating a spinner beside <label>,
# then prints a ✓ line on success. It preserves the command's exit status, so
# a failed download still fails closed. When stderr is not a TTY (CI, logs) it
# degrades to a single static "<label>…" line with no animation.
spin() {
    _label=$1; shift

    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
        *UTF-8*|*utf8*) _u=1 ;;
        *)              _u=0 ;;
    esac

    if [ ! -t 2 ]; then
        printf '📥  %s…\n' "$_label" >&2
        "$@"
        return $?
    fi

    "$@" &
    _sp=$!
    printf '\033[?25l' >&2                       # hide cursor
    _i=0
    while kill -0 "$_sp" 2>/dev/null; do
        printf '\r  %s  %s…' "$(_spin_frame "$_i" "$_u")" "$_label" >&2
        _i=$(( (_i + 1) % 10 ))
        sleep 0.1
    done
    wait "$_sp"; _st=$?
    printf '\033[?25h' >&2                        # restore cursor
    if [ "$_st" -eq 0 ]; then
        [ "$_u" = "1" ] && _mk='✓' || _mk='*'
        printf '\r\033[K📥  %s  %s\n' "$_mk" "$_label" >&2
    else
        printf '\r\033[K' >&2                     # clear; caller surfaces the error
    fi
    return $_st
}

# --- Resolve latest version if needed ---

if [ "${LOCAL_TARBALL:-}" = "" ] && [ "$VERSION" = "latest" ]; then
    echo "    resolving latest release…"
    if ! LATEST_JSON=$(fetch "https://releases.agentjail.io/v1/latest"); then
        echo "agentjail installer: release lookup failed; check your connection and retry." >&2
        exit 3
    fi
    VERSION=$(printf '%s' "$LATEST_JSON" \
              | grep '"version"' \
              | head -1 \
              | sed -E 's/.*"version":[ ]*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "agentjail installer: could not resolve latest release." >&2
        echo "  Check: https://github.com/${REPO}/releases" >&2
        exit 3
    fi
fi

echo "    version  ${VERSION}"

# --- Display changelog (best-effort, non-blocking) ---
# Extract changelog from the cached /v1/latest response.
# Uses simple grep/sed since jq may not be installed. The changelog field
# contains \n-escaped newlines; we convert the first few bullet points.
if [ -n "${LATEST_JSON:-}" ]; then
    _cl_raw=$(printf '%s' "$LATEST_JSON" | sed -n 's/.*"changelog":"\([^"]*\)".*/\1/p')
    if [ -n "$_cl_raw" ] && [ "$_cl_raw" != "null" ]; then
        # Extract only TL;DR bullets (between "## TL;DR" and first "###").
        _cl_bullets=$(printf '%s' "$_cl_raw" \
            | sed 's/\\n/\
/g' \
            | sed -n '/^## TL;DR/,/^###/p' \
            | grep -E '^[[:space:]]*[-*]' \
            | head -5 \
            | sed 's/^[[:space:]]*[-*][[:space:]]*//' \
            | sed 's/\*\*\([^*]*\)\*\*/\1/g' \
            | sed 's/`\([^`]*\)`/\1/g' \
            )
        if [ -n "$_cl_bullets" ]; then
            printf '\n    ── 📋 What'\''s new ───────────────────────────────────────────\n\n'
            printf '%s\n' "$_cl_bullets" \
                | while IFS= read -r _line; do printf '       • %s\n' "$_line"; done
            printf '\n       → https://github.com/%s/releases/tag/%s\n' "${REPO}" "${VERSION}"
            printf '\n    ────────────────────────────────────────────────────────────\n\n'
        fi
    fi
fi

# --- Set up temp dir with cleanup trap ---

TMP=$(mktemp -d)
# shellcheck disable=SC2064
rc_stage=
trap 'rm -rf "$TMP"; if [ -n "$rc_stage" ]; then rm -f "$rc_stage"; fi' EXIT

TARBALL="agentjail-${VERSION}-${PLATFORM}.tar.gz"

if [ -n "${LOCAL_TARBALL:-}" ]; then
    # Testing path: use a local tarball instead of fetching from GitHub.
    echo "using trusted local development tarball: ${LOCAL_TARBALL}"
    echo "⚠️  LOCAL_TARBALL skips release signature verification; use only your own trusted build." >&2
    cp "$LOCAL_TARBALL" "$TMP/$TARBALL"

    # Generate a local checksum manifest for the dry-run verification path.
    local_hash=$(sha256 "$TMP/$TARBALL" | awk '{print $1}')
    printf '%s  %s\n' "$local_hash" "$TARBALL" > "$TMP/SHA256SUMS"
else
    URL_BASE="https://releases.agentjail.io/download/${VERSION}"

    if ! spin "downloading ${TARBALL}" \
        fetch -o "$TMP/$TARBALL" "${URL_BASE}/${TARBALL}"; then
        echo "agentjail installer: archive download failed; check your connection and retry." >&2
        exit 3
    fi
    if ! fetch -o "$TMP/SHA256SUMS" "${URL_BASE}/SHA256SUMS"; then
        echo "agentjail installer: checksum download failed; retry the installer." >&2
        exit 3
    fi
    if ! fetch -o "$TMP/SHA256SUMS.minisig" "${URL_BASE}/SHA256SUMS.minisig"; then
        echo "agentjail installer: release signature unavailable; refusing this release." >&2
        exit 7
    fi
    if ! minisign -V -m "$TMP/SHA256SUMS" -x "$TMP/SHA256SUMS.minisig" -P "$SIGNING_PUBLIC_KEY" -q; then
        echo "agentjail installer: release signature verification failed; nothing extracted or executed." >&2
        exit 7
    fi
    echo "🔐  release signature verified"
fi

# --- Verify SHA256 ---

EXPECTED=$(awk -v name="$TARBALL" '$2 == name {print $1}' "$TMP/SHA256SUMS")
if [ -z "$EXPECTED" ]; then
    echo "agentjail installer: no SHA256 entry for '${TARBALL}' in checksum manifest." >&2
    exit 4
fi

ACTUAL=$(sha256 "$TMP/$TARBALL" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "agentjail installer: SHA256 mismatch!" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 5
fi
echo "🔐  checksum verified"

# --- Extract ---

tar -xzf "$TMP/$TARBALL" -C "$TMP"

if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] would install to ${INSTALL_DIR}"
    echo "[dry-run] extracted files:"
    ls "$TMP"
    echo "[dry-run] done — no changes made."
    exit 0
fi

# --- Install binaries ---
#
# As of the multicall-binary refactor, the tarball ships exactly two real
# binaries: agentjail (the multicall CLI, which also serves the daemon/
# shield/netproxy/secrets roles via argv[0] dispatch) and agentjail-hook (a
# separate, lean binary). The loop below still probes the legacy names too,
# purely for back-compat with an older tarball fetched via AGENTJAIL_VERSION
# or LOCAL_TARBALL — if a role binary happens to be shipped as a real file,
# it is installed as one; the symlink step further below then reconciles it
# (THE WATCHPOINT: never leave a stale real file at a role name after that
# step runs).

mkdir -p "$INSTALL_DIR"
INSTALLED=""
for bin in agentjail agentjail-hook agentjail-daemon agentjail-shield agentjail-netproxy agentjail-secrets; do
    if [ -f "$TMP/$bin" ]; then
        # Install atomically: stage into a temp file in the SAME dir, then
        # rename over the target. A plain `cp` rewrites the existing inode in
        # place — on a re-install macOS still holds a cached code signature
        # (AMFI) for that inode from the previously-executed binary, so the new
        # bytes fail validation and the next exec is SIGKILL'd ("Killed: 9").
        # A rename swaps in a fresh inode, so the signature validates cleanly
        # and it is safe even while the old daemon binary is still running.
        tmp_bin="$INSTALL_DIR/.$bin.tmp.$$"
        cp "$TMP/$bin" "$tmp_bin"
        chmod 0755 "$tmp_bin"
        mv -f "$tmp_bin" "$INSTALL_DIR/$bin"
        INSTALLED="${INSTALLED} $bin"
    fi
done
# shellcheck disable=SC2086  # intentional word-split to count installed binaries
set -- $INSTALLED
echo "✅  installed $# binaries  →  ${INSTALL_DIR}"

# --- Reconcile role binary symlinks ---
#
# agentjail-daemon, agentjail-shield, agentjail-netproxy, and agentjail-secrets
# are never real files — they are relative symlinks to agentjail in the same
# directory, so argv[0] dispatch (cmd/agentjail/main.go) routes to the right
# role regardless of which name the binary was invoked as. THE WATCHPOINT:
# remove whatever currently occupies a role path (a stale real file from a
# pre-refactor install, or an existing symlink) with rm -f — never `mv`/`cp`
# a real agentjail binary directly over a role path — then `ln -sf` a fresh
# relative symlink. This mirrors selfupdate.EnsureRoleSymlinks
# (internal/selfupdate/rolesymlinks.go), which the Go install/update paths use.
for role in agentjail-daemon agentjail-shield agentjail-netproxy agentjail-secrets; do
    rm -f "$INSTALL_DIR/$role"
    ln -sf agentjail "$INSTALL_DIR/$role"
done
echo "🔗  linked agentjail-daemon, agentjail-shield, agentjail-netproxy, agentjail-secrets → agentjail"

# --- Register hooks with detected coding agents ---
# The Go installer prints its own setup / discovery / summary sections below;
# a terminal shows the agent picker, piped installs wire all detected agents.

# Stamp the install method so the install telemetry event records how agentjail
# was installed ("curl" via this one-liner). Overridable, so a future brew
# formula can export AGENTJAIL_INSTALL_METHOD=brew before invoking the installer.
export AGENTJAIL_INSTALL_METHOD="${AGENTJAIL_INSTALL_METHOD:-curl}"

# Finish shell setup after a partial failure, then preserve the install exit status.
INSTALL_STATUS=0
if [ "${AGENTJAIL_ASSUME_YES:-0}" = "1" ]; then
    "$INSTALL_DIR/agentjail" install --yes || INSTALL_STATUS=$?
else
    "$INSTALL_DIR/agentjail" install || INSTALL_STATUS=$?
fi

# --- Put agentjail on PATH ---

AGENTJAIL_HOME_DIR="${AGENTJAIL_HOME:-$HOME/.agentjail}"
ENV_FILE="$AGENTJAIL_HOME_DIR/env"
FISH_ENV_FILE="$AGENTJAIL_HOME_DIR/env.fish"
shell_name=$(basename "${SHELL:-sh}")

# Quote literal paths; shell startup must never evaluate characters in a path.
quote_sh() {
    printf "'"
    printf '%s' "$1" | sed "s/'/'\\\\''/g"
    printf "'"
}
quote_fish() {
    printf "'"
    printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g"
    printf "'"
}

# shellcheck disable=SC2016
write_env_files() {
    quoted_bin=$(quote_sh "$INSTALL_DIR")
    {
        printf '# agentjail shell environment\n'
        printf 'case ":${PATH}:" in\n'
        printf '    *:%s:*) ;;\n' "$quoted_bin"
        printf '    *) export PATH=%s:"$PATH" ;;\n' "$quoted_bin"
        printf 'esac\n'
    } > "$ENV_FILE" || return 1
    printf 'fish_add_path --path --move --prepend %s\n' "$(quote_fish "$INSTALL_DIR")" > "$FISH_ENV_FILE"
}

RC_UPDATED=0
add_to_path() {
    [ "${AGENTJAIL_NO_MODIFY_PATH:-0}" = "1" ] && return 0
    case "$shell_name" in
        zsh) rc="${ZDOTDIR:-$HOME}/.zshrc" ;;
        bash)
            if [ "$OS" = "darwin" ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
        fish) rc="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
        *) rc="$HOME/.profile" ;;
    esac
    if [ "$shell_name" = "fish" ]; then
        line="source $(quote_fish "$FISH_ENV_FILE") # agentjail managed environment"
    else
        line=". $(quote_sh "$ENV_FILE") # agentjail managed environment"
    fi
    # Follow profile symlinks without replacing the user's link itself.
    rc_links=0
    while [ -L "$rc" ]; do
        rc_links=$((rc_links + 1))
        [ "$rc_links" -le 40 ] || return 1
        rc_link=$(readlink "$rc") || return 1
        case "$rc_link" in
            /*) rc=$rc_link ;;
            *) rc="$(dirname "$rc")/$rc_link" ;;
        esac
    done
    mkdir -p "$(dirname "$rc")" || return 1
    # Replace only our owned line, including the legacy default-directory line.
    if [ -f "$rc" ]; then
        awk '
            $0 == "# added by agentjail installer" {
                marker = $0
                if (getline > 0) {
                    if ($0 ~ /# agentjail managed environment$/ ||
                        $0 == "export PATH=\"$HOME/.agentjail/bin:$PATH\"" ||
                        $0 == "fish_add_path \"$HOME/.agentjail/bin\"") next
                    print marker
                    print
                } else print marker
                next
            }
            {print}
        ' "$rc" > "$TMP/shell-rc" || return 1
    else
        : > "$TMP/shell-rc"
    fi
    printf '# added by agentjail installer\n%s\n' "$line" >> "$TMP/shell-rc"
    rc_stage=$(mktemp "${rc}.agentjail.XXXXXX") || return 1
    if [ -f "$rc" ]; then
        cp -p "$rc" "$rc_stage" || return 1
    fi
    cat "$TMP/shell-rc" > "$rc_stage" || return 1
    mv -f "$rc_stage" "$rc" || return 1
    rc_stage=
    RC_UPDATED=1
}

if ! write_env_files; then
    echo "agentjail installer: could not write shell activation files." >&2
    INSTALL_STATUS=1
fi
if ! add_to_path; then
    echo "agentjail installer: could not update your shell profile; use the activation command below." >&2
    INSTALL_STATUS=1
fi

if [ "$INSTALL_STATUS" -eq 0 ]; then
    printf '\n✅  agentjail %s setup completed. Restart your agent to load its hooks.\n' "$VERSION"
else
    printf '\n⚠️  agentjail %s setup is incomplete; see errors above.\n' "$VERSION" >&2
fi
printf '    Run agentjail doctor before relying on protection.\n'
if [ "$shell_name" = "fish" ]; then
    activation="source $(quote_fish "$FISH_ENV_FILE")"
else
    activation=". $(quote_sh "$ENV_FILE")"
fi
printf '\nActivate the CLI in this shell:\n    %s\n' "$activation"
if [ "$RC_UPDATED" = "1" ]; then
    printf 'Or open a new terminal (your shell profile was updated).\n'
fi
printf '\nDiagnose without changing PATH:\n    %s doctor\n' "$(quote_sh "$INSTALL_DIR/agentjail")"

cat <<EOF

🚀  First protected session
      agentjail doctor                  check protection and recovery steps
      agentjail run -- codex             launch a sandboxed agent (or claude / agent)
      agentjail logs                     watch decisions in another terminal

📚  Docs  ·  https://github.com/${REPO}

EOF
exit "$INSTALL_STATUS"
