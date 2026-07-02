#!/usr/bin/env bash
#
# dev-deploy.sh -- build the 5 agentjail binaries from the current working tree
# and deploy them to the local install (~/.agentjail/bin), then (re)start the
# daemon. Works whether or not agentjail is already installed. Local dev only.
#
# It leans on `agentjail install`, which is idempotent: if agentjail is not
# installed it does a full install (launchd plist, hook wiring, starts the
# daemon); if it is installed it refreshes the hook + daemon and restarts. But
# `install` copies ONLY agentjail-hook and agentjail-daemon, so this script also
# hand-copies the three binaries install skips: agentjail (the CLI), the shield,
# and the netproxy.
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
ALL_BINARIES="agentjail agentjail-hook agentjail-daemon agentjail-shield agentjail-netproxy"

echo "==> building 5 binaries from $REPO_ROOT"
mkdir -p "$SRC"
for b in $ALL_BINARIES; do
	go build -ldflags="-s -w" -o "$SRC/$b" "$REPO_ROOT/cmd/$b"
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

# Swap ALL 5 binaries explicitly -- install only copies hook + daemon, and we want
# every binary (CLI, hook, daemon, shield, netproxy) to be this exact build so
# shield <-> netproxy stay token-compatible. Rename dodges "text file busy" on any
# binary currently mapped by a running process.
echo "==> swapping all 5 binaries into $BIN"
for b in $ALL_BINARIES; do
	cp "$SRC/$b" "$BIN/.$b.new"
	chmod +x "$BIN/.$b.new"
	mv -f "$BIN/.$b.new" "$BIN/$b"
	echo "    swapped $b"
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
