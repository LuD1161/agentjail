package proxyctl

import (
	"os"
	"path/filepath"
)

// controlSocketName is the fixed basename of the netproxy control socket.
const controlSocketName = "netproxy-ctl.sock"

// ControlSocketPath returns the absolute path of the netproxy control socket,
// at ~/.agentjail/run/netproxy-ctl.sock on every OS.
//
// REACHABILITY -- do not treat the path as the boundary. On macOS the shield
// denies network-outbound to it, but on Linux the agent CAN connect: Landlock is
// a filesystem LSM and does not mediate AF_UNIX connect() (the shield's own
// enforcement test records ctl_connect=ok). Authority-bearing verbs are gated by
// the ctlauth token instead; see ADR 0068.
//
// netproxy itself runs OUTSIDE the sandbox (started by the shield before the
// agent is exec'd), so it can create and bind the socket freely.
//
// If the home directory cannot be resolved (rare), it falls back to
// /tmp/agentjail-run/netproxy-ctl.sock, mirroring the daemon socket's /tmp
// fallback (wire.DefaultSocketPath).
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
	return ControlSocketDirForHome(home)
}

// ControlSocketDirForHome is ControlSocketDir with an explicit home directory.
// The macOS sbpl generator uses this so its network-outbound deny targets the
// same path regardless of how home is resolved (and so tests are deterministic).
func ControlSocketDirForHome(home string) string {
	return filepath.Join(home, ".agentjail", "run")
}

// ControlSocketPathForHome is ControlSocketPath with an explicit home directory.
func ControlSocketPathForHome(home string) string {
	return filepath.Join(ControlSocketDirForHome(home), controlSocketName)
}
