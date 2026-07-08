#!/usr/bin/env bash
# guest-provision.sh — runs INSIDE a testbed guest (pushed by testbed.sh provision).
#
# Turns a clean box into "a real dev machine that just installed agentjail":
#   1. Claude Code via npm (the way a human installs it)
#   2. optional login seeding via CLAUDE_CODE_OAUTH_TOKEN
#   3. agentjail via the SHIPPED install.sh (LOCAL_TARBALL seam) — the true
#      user path: checksum verify, ~/.agentjail/bin, service install, hook merge
#   4. a realistic seed project (~/work/demo) with allowed + forbidden remotes

set -euo pipefail

log() { echo "==> [guest] $*"; }

# ---- 1. Claude Code ---------------------------------------------------------

if ! command -v claude >/dev/null 2>&1; then
    log "installing Claude Code via npm"
    # brew-installed node on macOS owns its prefix - no sudo needed.
    # System-packaged node on Linux needs sudo for global installs.
    if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
        npm install -g @anthropic-ai/claude-code
    else
        sudo npm install -g @anthropic-ai/claude-code
    fi
else
    log "Claude Code already installed: $(claude --version 2>/dev/null || true)"
fi

# agentjail's Claude Code detection requires ~/.claude to exist.
mkdir -p "$HOME/.claude"
[ -f "$HOME/.claude/settings.json" ] || echo '{}' > "$HOME/.claude/settings.json"

# ---- 2. Credential seeding (optional) ----------------------------------------

if [ -f /tmp/claude-token ]; then
    log "seeding CLAUDE_CODE_OAUTH_TOKEN"
    install -m 0600 /tmp/claude-token "$HOME/.claude-token"
    rm -f /tmp/claude-token
    # macOS default shell is zsh (reads ~/.zprofile); Linux uses bash.
    rcfile="$HOME/.bashrc"
    if [ "$(uname -s)" = "Darwin" ]; then
        rcfile="$HOME/.zprofile"
    fi
    if ! grep -q CLAUDE_CODE_OAUTH_TOKEN "$rcfile" 2>/dev/null; then
        printf '\n# agentjail testbed: Claude Code login\nexport CLAUDE_CODE_OAUTH_TOKEN="$(cat "$HOME/.claude-token")"\n' >> "$rcfile"
    fi
else
    log "no token pushed — Claude Code installed but not logged in"
fi

# ---- 3. agentjail via the shipped installer -----------------------------------

log "running install.sh with LOCAL_TARBALL (the real user path)"
LOCAL_TARBALL=/tmp/agentjail-local.tar.gz sh /tmp/agentjail-install.sh

# macOS Gatekeeper quarantines unsigned binaries copied from outside.
# Strip the quarantine xattr so they can execute without code-signing.
if [ "$(uname -s)" = "Darwin" ] && [ -d "$HOME/.agentjail/bin" ]; then
    log "clearing Gatekeeper quarantine on agentjail binaries"
    xattr -dr com.apple.quarantine "$HOME/.agentjail/bin" 2>/dev/null || true
fi

# install.sh already ran `agentjail install` (non-tty wires all detected
# agents). Re-run explicitly for claude-code to be deterministic + idempotent.
log "agentjail install --for claude-code"
"$HOME/.agentjail/bin/agentjail" install --for claude-code || true

# ---- 4. Seed project ----------------------------------------------------------

if [ ! -d "$HOME/work/demo" ]; then
    log "creating seed project ~/work/demo (allowed + forbidden git remotes)"
    mkdir -p "$HOME/work/remotes"
    git init --bare -q "$HOME/work/remotes/allowed.git"
    git init --bare -q "$HOME/work/remotes/forbidden.git"
    mkdir -p "$HOME/work/demo" && cd "$HOME/work/demo"
    git init -q
    git config user.name "Testbed User"
    git config user.email "testbed@example.invalid"
    echo "# demo" > README.md
    echo "print('hello')" > app.py
    git add -A && git commit -qm "initial commit"
    git remote add origin "$HOME/work/remotes/allowed.git"
    git remote add exfil "$HOME/work/remotes/forbidden.git"
    git push -q origin main 2>/dev/null || git push -q origin master
    echo "uncommitted change" >> app.py   # a dirty file, like a real project
fi

# ---- Verify -------------------------------------------------------------------

log "verification:"
"$HOME/.agentjail/bin/agentjail" status || true
log "done. This box now looks like a fresh dev machine with agentjail + Claude Code."
