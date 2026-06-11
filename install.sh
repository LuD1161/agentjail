#!/bin/sh
# install.sh — agentjail one-liner installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/LuD1161/agentjail/main/install.sh | sh
#
# Environment overrides:
#   AGENTJAIL_VERSION     — pin to a specific tag (default: latest)
#   AGENTJAIL_HOME        — installation root (default: $HOME/.agentjail)
#   AGENTJAIL_DRY_RUN     — set to 1 to skip actual install; verify download+checksum only
#   LOCAL_TARBALL          — path to a local tarball; skips network fetch (for testing)
#
# POSIX sh — no bash-isms; passes shellcheck.
set -eu

REPO="LuD1161/agentjail"
VERSION="${AGENTJAIL_VERSION:-latest}"
INSTALL_DIR="${AGENTJAIL_HOME:-$HOME/.agentjail}/bin"
DRY_RUN="${AGENTJAIL_DRY_RUN:-0}"

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
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
              | grep '"tag_name"' \
              | head -1 \
              | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "agentjail installer: could not resolve latest release." >&2
        echo "  Check: https://github.com/${REPO}/releases" >&2
        exit 3
    fi
fi

echo "    version  ${VERSION}"

# --- Set up temp dir with cleanup trap ---

TMP=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

TARBALL="agentjail-${VERSION}-${PLATFORM}.tar.gz"

if [ -n "${LOCAL_TARBALL:-}" ]; then
    # Testing path: use a local tarball instead of fetching from GitHub.
    echo "using local tarball: ${LOCAL_TARBALL}"
    cp "$LOCAL_TARBALL" "$TMP/$TARBALL"

    # Generate a local checksum manifest for the dry-run verification path.
    (cd "$(dirname "$LOCAL_TARBALL")" && sha256 "$(basename "$LOCAL_TARBALL")") \
        | sed "s|$(basename "$LOCAL_TARBALL")|$TARBALL|" \
        > "$TMP/SHA256SUMS"
else
    URL_BASE="https://github.com/${REPO}/releases/download/${VERSION}"

    spin "downloading ${TARBALL}" \
        curl -fsSL -o "$TMP/$TARBALL" "${URL_BASE}/${TARBALL}"
    curl -fsSL -o "$TMP/SHA256SUMS" "${URL_BASE}/SHA256SUMS"
fi

# --- Verify SHA256 ---

EXPECTED=$(grep "  ${TARBALL}$" "$TMP/SHA256SUMS" | awk '{print $1}')
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

mkdir -p "$INSTALL_DIR"
INSTALLED=""
for bin in agentjail agentjail-hook agentjail-daemon agentjail-shield agentjail-netproxy; do
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

# --- Register hooks with detected coding agents ---
# The Go installer prints its own setup / discovery / summary sections below;
# a terminal shows the agent picker, piped installs wire all detected agents.

# Stamp the install method so the install telemetry event records how agentjail
# was installed ("curl" via this one-liner). Overridable, so a future brew
# formula can export AGENTJAIL_INSTALL_METHOD=brew before invoking the installer.
export AGENTJAIL_INSTALL_METHOD="${AGENTJAIL_INSTALL_METHOD:-curl}"

"$INSTALL_DIR/agentjail" install

# --- Put agentjail on PATH (default on; opt out: AGENTJAIL_NO_MODIFY_PATH=1) ---

AGENTJAIL_HOME_DIR="${AGENTJAIL_HOME:-$HOME/.agentjail}"
ENV_FILE="$AGENTJAIL_HOME_DIR/env"

# write_env_file drops a rustup-style script. `source $HOME/.agentjail/env` puts
# agentjail on PATH in the CURRENT shell, independent of which rc the user has.
# The INSTALL_DIR is baked as an absolute literal (correct under a custom
# AGENTJAIL_HOME), and the case guard makes re-sourcing idempotent.
# shellcheck disable=SC2016  # ${PATH}/$PATH are written literally into the script on purpose
write_env_file() {
    {
        printf '# agentjail shell environment. Put `agentjail` on your PATH with:\n'
        printf '#   source "%s"\n' "$ENV_FILE"
        printf 'case ":${PATH}:" in\n'
        printf '    *":%s:"*) ;;\n' "$INSTALL_DIR"
        printf '    *) export PATH="%s:$PATH" ;;\n' "$INSTALL_DIR"
        printf 'esac\n'
    } > "$ENV_FILE" 2>/dev/null
}

# add_to_path appends a single marked, idempotent line to the login shell's rc
# (zsh/bash/fish) so `agentjail` is on PATH in FUTURE shells. Best-effort and
# SILENT — all user-facing guidance is printed by the final block below.
# Honors AGENTJAIL_NO_MODIFY_PATH=1 (the env file is still written either way).
# shellcheck disable=SC2016  # $HOME/$PATH are written into the rc literally on purpose
add_to_path() {
    [ "${AGENTJAIL_NO_MODIFY_PATH:-0}" = "1" ] && return 0
    case ":${PATH}:" in *":${INSTALL_DIR}:"*) return 0 ;; esac

    shell_name=$(basename "${SHELL:-sh}")
    case "$shell_name" in
        zsh)
            rc="${ZDOTDIR:-$HOME}/.zshrc"
            line='export PATH="$HOME/.agentjail/bin:$PATH"'
            ;;
        bash)
            if [ "$(uname -s)" = "Darwin" ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi
            line='export PATH="$HOME/.agentjail/bin:$PATH"'
            ;;
        fish)
            rc="$HOME/.config/fish/config.fish"
            line='fish_add_path "$HOME/.agentjail/bin"'
            ;;
        *)
            rc="$HOME/.profile"
            line='export PATH="$HOME/.agentjail/bin:$PATH"'
            ;;
    esac

    # Idempotent: skip if our marker is already in the rc file.
    if [ -f "$rc" ] && grep -q 'added by agentjail installer' "$rc" 2>/dev/null; then
        return 0
    fi
    mkdir -p "$(dirname "$rc")" 2>/dev/null && \
        printf '\n# added by agentjail installer\n%s\n' "$line" >> "$rc" 2>/dev/null
}

# --- Done — write env file, edit rc, then print a clear conditional next step ---

write_env_file
add_to_path

printf '\n🎉  agentjail %s installed — the hook is active now.\n' "${VERSION}"
printf '    (enforcement uses an absolute path; PATH below is only for the `agentjail` CLI)\n'

if command -v agentjail >/dev/null 2>&1; then
    # Already resolvable (reinstall, or INSTALL_DIR was already on PATH).
    printf '\n✅  Ready — run:  agentjail status\n'
else
    printf '\n┌─ One step to use the `agentjail` command ─────────────────────\n'
    printf '│\n'
    printf '│   source %s\n' "$ENV_FILE"
    printf '│       …or just open a new terminal (your shell rc was updated)\n'
    printf '│\n'
    printf '│   then:  agentjail status\n'
    printf '│\n'
    printf '│   ▶ or run it right now, no PATH needed:\n'
    printf '│       %s/agentjail status\n' "$INSTALL_DIR"
    if [ "${AGENTJAIL_NO_MODIFY_PATH:-0}" = "1" ]; then
        printf '│\n'
        printf '│   (AGENTJAIL_NO_MODIFY_PATH=1 — your shell rc was left untouched)\n'
    fi
    printf '└───────────────────────────────────────────────────────────────\n'
fi

cat <<EOF

🚀  Quick start
      agentjail status        verify daemon + hook
      agentjail logs          watch decisions live

📚  Docs  ·  https://github.com/${REPO}

EOF
