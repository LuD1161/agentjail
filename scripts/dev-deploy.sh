#!/usr/bin/env bash
#
# dev-deploy.sh -- build the 5 agentjail cmd/ packages from the current working
# tree (compile-verification for each thin per-role wrapper) and deploy the
# REAL binaries to the local install (~/.agentjail/bin), then (re)start the
# daemon. Works whether or not agentjail is already installed. Local dev only.
#
# As of the multicall-binary refactor, agentjail ships exactly two real
# binaries -- agentjail (the multicall CLI, which also serves the daemon/
# shield/netproxy/secrets roles via argv[0] dispatch) and agentjail-hook.
# agentjail-daemon, agentjail-shield, agentjail-netproxy, and agentjail-secrets
# are relative symlinks to agentjail, never real files (THE WATCHPOINT: never
# `cp`/`mv` a real binary over one of those four names). `agentjail install`
# (which this script runs) copies agentjail + agentjail-hook and reconciles
# the four symlinks itself, so this script only needs to explicitly swap the
# two real binaries + re-affirm the symlinks -- it must NOT deploy separate
# real agentjail-daemon/shield/netproxy binaries, even though it still builds
# those cmd/ packages below (kept for compile verification; the daemon/shield/
# netproxy logic they wrap is identical to what's already inside the agentjail
# binary via internal/{daemonapp,shieldapp,netproxyapp,secretsapp}).
#
# IMPORTANT: run this from a plain terminal, NOT from inside a shielded agent
# session -- agentjail's command policy deliberately blocks the agent from
# modifying its own enforcement binaries or killing its daemon. That guardrail is
# working as intended; this script is the human-side escape hatch.
#
# Usage:  ./scripts/dev-deploy.sh        (or: make dev-deploy)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/bin"
BIN="${AGENTJAIL_HOME:-$HOME/.agentjail}/bin"
# All 5 cmd/ packages are built for compile verification. Only REAL_BINARIES
# (agentjail, agentjail-hook) are ever deployed as real files to $BIN -- the
# other 3 are role symlinks to agentjail (see header comment above).
ALL_BINARIES="agentjail agentjail-hook agentjail-daemon agentjail-shield agentjail-netproxy"
REAL_BINARIES="agentjail agentjail-hook"
ROLE_SYMLINKS="agentjail-daemon agentjail-shield agentjail-netproxy agentjail-secrets"

# Embed the git-describe version so `agentjail statusline` shows "<tag>+N" (N
# commits past the last release) instead of a bare hash. Harmless on the
# binaries that lack a main.version symbol -- the linker ignores an unset -X.
VERSION="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || true)"

echo "==> building 5 binaries from $REPO_ROOT (version: ${VERSION:-unset})"
mkdir -p "$SRC"
for b in $ALL_BINARIES; do
	go build -ldflags="-X main.version=$VERSION -s -w" -o "$SRC/$b" "$REPO_ROOT/cmd/$b"
	echo "    built $b"
done

# Stop ALL running netproxies so the freshly-built one is spawned on the next
# shielded launch. A pre-session-aware netproxy (the --policy one, no control
# socket) MUST go or a session-aware shield fails closed against it; an old-build
# session-aware one is killed too so its stale code is not reused via fingerprint.
# Active shielded sessions will need a relaunch afterwards.
echo "==> stopping any running netproxy"
if pkill -f '/agentjail-netproxy' 2>/dev/null; then
	echo "    stopped running netproxy (relaunch shielded sessions)"
else
	echo "    none running"
fi

# install-or-refresh: on a fresh box this creates the launchd plist + wires the
# hooks (and copies hook + daemon + starts the daemon). On an already-installed
# box it just refreshes that wiring. Run the freshly-built CLI so it finds its
# dev siblings in $SRC.
echo "==> agentjail install (idempotent: installs if absent, refreshes if present)"
"$SRC/agentjail" install

# Swap the 2 real binaries explicitly (install already did this using the
# colocated $SRC build, so this is belt-and-suspenders) and re-affirm the 4
# role symlinks. Rename dodges "text file busy" on any binary currently mapped
# by a running process. THE WATCHPOINT: never write a real file at a role
# name -- shield/netproxy/secrets all dispatch through the SAME agentjail
# binary swapped in here, via argv[0] (see cmd/agentjail/main.go), so keeping
# them as symlinks is what makes this exact dev build take effect for every
# role at once.
echo "==> swapping $REAL_BINARIES into $BIN"
for b in $REAL_BINARIES; do
	cp "$SRC/$b" "$BIN/.$b.new"
	chmod +x "$BIN/.$b.new"
	mv -f "$BIN/.$b.new" "$BIN/$b"
	echo "    swapped $b"
done

echo "==> reconciling role symlinks (agentjail-daemon/shield/netproxy/secrets -> agentjail)"
for role in $ROLE_SYMLINKS; do
	rm -f "$BIN/$role"
	ln -sf agentjail "$BIN/$role"
	echo "    linked $role -> agentjail"
done

# Restart the daemon so it loads the freshly-swapped daemon binary (install may
# have started the pre-swap one, or an old one may still be live).
echo "==> restarting the daemon to load the swapped binary"
case "$(uname -s)" in
Darwin)
	launchctl kickstart -k "gui/$(id -u)/com.agentjail.daemon" 2>/dev/null \
		&& echo "    launchd kickstart com.agentjail.daemon" \
		|| { pkill -f '/agentjail-daemon' 2>/dev/null || true; echo "    no launchd job; killed daemon (it should respawn)"; }
	;;
Linux)
	systemctl --user restart agentjail-daemon 2>/dev/null \
		&& echo "    systemctl --user restart agentjail-daemon" \
		|| { pkill -f '/agentjail-daemon' 2>/dev/null || true; echo "    killed daemon (restart via your supervisor)"; }
	;;
*)
	pkill -f '/agentjail-daemon' 2>/dev/null || true
	;;
esac

sleep 1
echo "==> now running:"
pgrep -fl 'agentjail-daemon|agentjail-netproxy' || echo "    (daemon still starting; netproxy starts on the next shielded 'claude' launch)"
echo "==> done. Next 'claude' launch uses the new shield + spawns the session-aware netproxy on :9100."
