package proxyctl

import (
	"os"
	"path/filepath"
)

// controlSocketName is the fixed basename of the netproxy control socket.
const controlSocketName = "netproxy-ctl.sock"

// ControlSocketPath returns the absolute path of the netproxy control socket.
//
// It lives at ~/.agentjail/run/netproxy-ctl.sock on every OS. This location is
// unreachable by the sandboxed agent by construction:
//
//   - Linux: ~/.agentjail is granted READ-ONLY to the agent (see
//     shield_agentpaths.go). AF_UNIX connect() requires WRITE access to the
//     socket inode, which the read-only grant does not confer -- and, unlike
//     ~/.agentjail/daemon.sock, this socket gets NO single-file write grant. So
//     the agent can stat/list the path but cannot connect() it. (This is the
//     exact inverse of the daemon.sock write grant, and is proven by a Landlock
//     enforcement test.)
//   - macOS: ~/.agentjail is file read/write denied, and the shield additionally
//     emits an explicit (deny network-outbound (literal <path>)) because Seatbelt
//     models AF_UNIX connect() as a network op under an allow-default base.
//
// netproxy itself runs OUTSIDE the sandbox (started by the shield before the
// agent is exec'd), so it can create and bind the socket freely.
//
// If the home directory cannot be resolved (rare), it falls back to
// /tmp/agentjail-run/netproxy-ctl.sock, mirroring the daemon socket's /tmp
// fallback (wire.DefaultSocketPath). NOTE: on Linux the agent has a read-write
// grant on /tmp, so in that degenerate no-home case the control socket is NOT
// connect-protected by the filesystem sandbox; this matches the equivalent
// daemon-socket limitation and is acceptable only because it requires an
// unresolvable HOME.
func ControlSocketPath() string {
	return filepath.Join(ControlSocketDir(), controlSocketName)
}

// ControlSocketDir returns the directory that holds the control socket. netproxy
// creates it (0700) before binding; the shield reads the path to connect and,
// on macOS, to emit the network-outbound deny.
func ControlSocketDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/agentjail-run"
	}
	return filepath.Join(home, ".agentjail", "run")
}
