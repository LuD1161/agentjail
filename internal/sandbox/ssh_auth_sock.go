package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SSHAuthSock is an inherited SSH agent endpoint that passed launch-time
// validation. Its zero value deliberately carries no capability.
type SSHAuthSock struct {
	Path string
}

// SSHAuthSockPolicy identifies paths the shield owns and must never grant to
// an agent as an SSH signing endpoint.
type SSHAuthSockPolicy struct {
	ForbiddenDirs []string
}

// ValidateSSHAuthSock accepts only an absolute, clean AF_UNIX socket path.
// Platform code additionally verifies its ownership, type, and every path
// component without following symlinks.
func ValidateSSHAuthSock(path string, policy SSHAuthSockPolicy) (SSHAuthSock, error) {
	if path == "" {
		return SSHAuthSock{}, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || hasControlChar(path) {
		return SSHAuthSock{}, fmt.Errorf("not a clean absolute path")
	}
	for _, dir := range policy.ForbiddenDirs {
		if dir == "" {
			continue
		}
		cleanDir := filepath.Clean(dir)
		if path == cleanDir || strings.HasPrefix(path, cleanDir+string(filepath.Separator)) {
			return SSHAuthSock{}, fmt.Errorf("names a shield control path")
		}
	}
	return validateSSHAuthSockOnDisk(path)
}

// AppendSSHAuthSock adds only a previously validated endpoint to an agent
// environment. SSH_AUTH_SOCK is intentionally absent from the baseline.
func AppendSSHAuthSock(env []string, sock SSHAuthSock) []string {
	if sock.Path == "" {
		return env
	}
	return append(env, "SSH_AUTH_SOCK="+sock.Path)
}

// ReplaceSSHAgentEnv removes every ambient SSH delegation variable before
// appending the shield's validated capability. Policy env_passthrough must not
// re-admit a host-supplied socket, git override, or delegation marker.
func ReplaceSSHAgentEnv(env []string, sock SSHAuthSock, delegationEnv string) []string {
	env = RemoveEnvKeys(env, "SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE", delegationEnv)
	return AppendSSHAuthSock(env, sock)
}
