package grantctl

import (
	"os"
	"path/filepath"
)

// controlSocketName is the fixed basename of the daemon grant control socket.
const controlSocketName = "daemon-ctl.sock"

// controlLockName is the fixed basename of the daemon control lock file.
const controlLockName = "daemon-ctl.lock"

// ControlSocketPath returns the absolute path of the daemon grant control
// socket, at ~/.agentjail/run/daemon-ctl.sock on every OS.
//
// REACHABILITY — read this before putting a privileged verb here:
//
//   - macOS: the shield explicitly denies network-outbound to this path, so a
//     sandboxed agent genuinely cannot connect.
//   - Linux: the agent CAN connect. Landlock is a filesystem LSM and does not
//     mediate AF_UNIX connect(), so leaving the socket outside the allowlist
//     withholds nothing. This is proven, not theorised: the shield's own
//     Landlock enforcement test observes ctl_connect=ok and records it as a
//     known limitation (shield_linux_enforce_test.go, "grant-socket isolation
//     needs Tier 2+"). An earlier version of this comment claimed the opposite
//     and was believed; it is what let ADR 0066 ship a Linux no-op.
//
// So on Linux the only thing standing between a prompt-injected agent and this
// socket's verbs is the same-UID peer check — which the agent passes, since it
// runs as the daemon's UID. SO_PEERCRED is identity, not authorization.
//
// Consequence: grant_approve, grant_deny, grant_list, and daemon_reload are all
// agent-reachable on Linux today. Path separation is a real boundary on macOS
// and a structural one on Linux. Closing it needs a secret the sandbox cannot
// read — Landlock DOES mediate file reads (see AgentjailSecretsProtectedNames),
// so a token under a read-denied child of ~/.agentjail is the available fix.
//
// The daemon itself runs outside the sandbox and creates/binds the socket
// freely.
//
// If the home directory cannot be resolved (rare), it falls back to
// /tmp/agentjail-run/daemon-ctl.sock, mirroring the daemon socket's /tmp
// fallback (wire.DefaultSocketPath). NOTE: on Linux the agent may have
// read-write access to /tmp, so in that degenerate no-home case the control
// socket is not filesystem-protected by the sandbox; this matches the
// equivalent daemon-socket limitation and is acceptable only because it
// requires an unresolvable HOME.
func ControlSocketPath() string {
	return filepath.Join(ControlSocketDir(), controlSocketName)
}

// ControlSocketDir returns the directory that holds the daemon control socket.
// The daemon creates it (0700) before binding.
func ControlSocketDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/agentjail-run"
	}
	return ControlSocketDirForHome(home)
}

// ControlSocketDirForHome is ControlSocketDir with an explicit home directory.
// The macOS sbpl generator uses this so the network-outbound deny targets the
// same path regardless of how home is resolved (and so tests are deterministic).
func ControlSocketDirForHome(home string) string {
	return filepath.Join(home, ".agentjail", "run")
}

// ControlSocketPathForHome is ControlSocketPath with an explicit home directory.
// The macOS sbpl generator and tests use this for deterministic path generation.
func ControlSocketPathForHome(home string) string {
	return filepath.Join(ControlSocketDirForHome(home), controlSocketName)
}

// ControlLockName returns the basename of the daemon control lock file.
// The lock is held by the daemon to coordinate exclusive access to the grant
// queue (or other critical sections). It lives in the same directory as the
// control socket.
func ControlLockName() string {
	return controlLockName
}

// ControlLockPath returns the absolute path of the daemon control lock file.
func ControlLockPath() string {
	return filepath.Join(ControlSocketDir(), ControlLockName())
}

// ControlLockPathForHome returns the absolute path of the daemon control lock
// file with an explicit home directory. The macOS sbpl generator uses this.
func ControlLockPathForHome(home string) string {
	return filepath.Join(ControlSocketDirForHome(home), ControlLockName())
}
