#!/usr/bin/env bash
# guest-provision.sh — runs INSIDE a testbed guest (pushed by testbed.sh provision).
#
# Turns a clean box into "a real dev machine that just installed agentjail":
#   1. Claude Code via npm (the way a human installs it)
#   2. optional Claude login seeding and Codex CLI installation
#   3. agentjail via the SHIPPED install.sh (LOCAL_TARBALL seam) — the true
#      user path: checksum verify, ~/.agentjail/bin, service install, hook merge
#   4. a realistic seed project (~/work/demo) with allowed + forbidden remotes

set -euo pipefail

log() { echo "==> [guest] $*"; }

# ---- 0a. transparent-tunnel prerequisite ------------------------------------
# Ubuntu 23.10+ (incl. 24.04 noble, this template's image) ships
# kernel.apparmor_restrict_unprivileged_userns=1. We deliberately DO NOT relax
# it globally — that would weaken userns for every binary. The tunnel is enabled
# instead via a scoped AppArmor profile for agentjail-shield alone, loaded AFTER
# agentjail is installed (step 3a below), with the restriction LEFT ON. That is
# the real user path on modern Ubuntu. See ADR 0104-shield-apparmor-userns.

# ---- 0. recording niceties --------------------------------------------------
# Each CLI recording opens with a system-info banner for context (mirrors the
# macOS suite, which uses fastfetch). Ubuntu's apt ships neofetch, not
# fastfetch, so Linux uses neofetch as the equivalent opener.
if [ "$(uname -s)" = "Linux" ] && ! command -v neofetch >/dev/null 2>&1; then
    log "installing neofetch (recording banner)"
    sudo apt-get install -y -q neofetch >/dev/null 2>&1 || log "neofetch install failed (non-fatal)"
fi

# A git identity so a real agent task ("build X and commit it") doesn't stall
# asking for user.name/user.email inside the sandboxed session.
git config --global user.name  "Testbed Agent" 2>/dev/null || true
git config --global user.email "agent@testbed.local" 2>/dev/null || true

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

# Merge any host-synced MCP servers into ~/.claude.json (Claude Code's global
# config). node is guaranteed here (Claude Code needs it); the guest has no jq.
if [ -f /tmp/claude-mcp.json ]; then
    log "syncing MCP servers into ~/.claude.json"
    node -e '
        const fs = require("fs");
        const dst = process.env.HOME + "/.claude.json";
        const add = (JSON.parse(fs.readFileSync("/tmp/claude-mcp.json", "utf8")).mcpServers) || {};
        let cur = {};
        try { cur = JSON.parse(fs.readFileSync(dst, "utf8")); } catch (e) {}
        cur.mcpServers = Object.assign({}, cur.mcpServers || {}, add);
        fs.writeFileSync(dst, JSON.stringify(cur, null, 2));
        console.log("==> [guest] merged MCP servers: " + Object.keys(add).join(", "));
    '
    rm -f /tmp/claude-mcp.json
fi

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

# Codex is installed only for the explicit live-agent approval scenario.
# Authentication is injected later by the scenario runner.
if [ "${AGENTJAIL_TESTBED_CODEX:-0}" = "1" ]; then
    if ! command -v codex >/dev/null 2>&1 || [ "$(codex --version 2>/dev/null)" != "codex-cli 0.146.0" ]; then
        log "installing Codex CLI 0.146.0 for approval compatibility"
        if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
            npm install -g @openai/codex@0.146.0
        else
            sudo npm install -g @openai/codex@0.146.0
        fi
    fi
    mkdir -p "$HOME/.codex"
    chmod 700 "$HOME/.codex"
else
    log "Codex compatibility install not requested"
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

# The Codex approval matrix models users who launch through the opt-in PATH
# shim. This is a separate consented install action, not a second base install.
# See ADR 0119-command-approval-transport.
if [ "${AGENTJAIL_TESTBED_CODEX:-0}" = "1" ]; then
    log "installing the opt-in Codex PATH shim for approval compatibility"
    "$HOME/.agentjail/bin/agentjail" install --with-path-shim
fi

# ---- 3a. scoped AppArmor userns profile (modern Ubuntu, restriction LEFT ON) --
# Load the per-binary profile so --tunnel works without weakening the machine.
# Non-restricted hosts (Debian/Fedora/older Ubuntu) skip this entirely. Consent
# is pre-granted for the unattended testbed via AGENTJAIL_ASSUME_YES. The global
# restriction stays ON — the profile is what makes the tunnel work, and the
# tunnel-agent gate must go green with it on. See ADR 0104-shield-apparmor-userns.
if [ "$(uname -s)" = "Linux" ] \
    && [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ]; then
    log "installing scoped AppArmor userns profile (restriction left ON)"
    command -v apparmor_parser >/dev/null 2>&1 || sudo apt-get install -y -q apparmor-utils >/dev/null 2>&1 || true
    sudo env AGENTJAIL_ASSUME_YES=1 "$HOME/.agentjail/bin/agentjail" install --with-apparmor \
        || log "install --with-apparmor failed — tunnel will be unavailable on this host"
fi

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
status_output="$("$HOME/.agentjail/bin/agentjail" status)"
printf '%s\n' "$status_output"

# The shipped installer must leave the machine usable immediately. Running a
# second install here would test reinstall recovery, not the clean user path.
# See ADR 0053-vm-testbed-engine.
if ! printf '%s\n' "$status_output" | grep -q 'daemon.*running' \
    || printf '%s\n' "$status_output" | grep -q 'daemon.*not running'; then
    log "verification failed: the clean install did not leave the daemon running"
    exit 1
fi
if ! printf '%s\n' "$status_output" | grep -q 'Claude Code.*installed'; then
    log "verification failed: the clean install did not wire Claude Code"
    exit 1
fi
if [ "${AGENTJAIL_TESTBED_CODEX:-0}" = "1" ] \
    && ! printf '%s\n' "$status_output" | grep -q 'Codex.*installed'; then
    log "verification failed: the clean install did not wire Codex"
    exit 1
fi
log "done. This box now looks like a fresh dev machine with agentjail + Claude Code."
