package shieldapp

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/internal/sandbox"
	"github.com/LuD1161/agentjail/internal/sshagent"
	"golang.org/x/crypto/ssh/agent"
)

// sshAgentDelegatedEnv is shield-injected only after validated delegation.
// It must never enter the baseline environment.
const sshAgentDelegatedEnv = sshagent.DelegationEnv + "=1"

type gitSSHLaunchMode uint8

const (
	gitSSHDisabled gitSSHLaunchMode = iota
	gitSSHAutomatic
	gitSSHExplicit
)

// resolveGitSSHLaunchMode applies per-launch flags over the standing policy.
func resolveGitSSHLaunchMode(policyEnabled, gitSSH, noGitSSH bool) (gitSSHLaunchMode, error) {
	if gitSSH && noGitSSH {
		return gitSSHDisabled, fmt.Errorf("--git-ssh and --no-git-ssh cannot be combined")
	}
	if gitSSH {
		return gitSSHExplicit, nil
	}
	if noGitSSH || !policyEnabled {
		return gitSSHDisabled, nil
	}
	return gitSSHAutomatic, nil
}

// selectSSHAgentForwarding turns an inherited socket into a validated launch
// capability. It never scans for agents and validation is not authorization:
// forwarding exposes every identity the host agent offers.
func selectSSHAgentForwarding(forward bool, path, home string) (sandbox.SSHAuthSock, error) {
	if !forward {
		return sandbox.SSHAuthSock{}, nil
	}
	if home == "" {
		return sandbox.SSHAuthSock{}, fmt.Errorf("cannot validate SSH_AUTH_SOCK without a home directory")
	}
	sock, err := sandbox.ValidateSSHAuthSock(path, sandbox.SSHAuthSockPolicy{
		ForbiddenDirs: []string{filepath.Join(home, ".agentjail")},
	})
	if err != nil {
		return sandbox.SSHAuthSock{}, fmt.Errorf("refusing SSH agent forwarding: %w", err)
	}
	if sock.Path == "" {
		return sandbox.SSHAuthSock{}, fmt.Errorf("refusing SSH agent forwarding: SSH_AUTH_SOCK is empty")
	}
	if _, err := probeSSHAgent(sock); err != nil {
		return sandbox.SSHAuthSock{}, fmt.Errorf("refusing SSH agent forwarding: socket did not answer the SSH-agent identity protocol: %w", err)
	}
	return sock, nil
}

func prepareSSHAgentForwarding(forward bool) (sandbox.SSHAuthSock, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return sandbox.SSHAuthSock{}, fmt.Errorf("determine home for SSH agent forwarding: %w", err)
	}
	return selectSSHAgentForwarding(forward, os.Getenv("SSH_AUTH_SOCK"), home)
}

const sshAgentProbeTimeout = 150 * time.Millisecond

// probeSSHAgent verifies the SSH-agent identities protocol without asking the
// agent to sign. It establishes liveness only; it cannot attest the peer, an
// identity's intended host, or a repository's authorization.
func probeSSHAgent(sock sandbox.SSHAuthSock) (sshagent.Readiness, error) {
	conn, err := net.DialTimeout("unix", sock.Path, sshAgentProbeTimeout)
	if err != nil {
		return sshagent.ReadinessNoAgent, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(sshAgentProbeTimeout)); err != nil {
		return sshagent.ReadinessNoAgent, err
	}
	identities, err := agent.NewClient(conn).List()
	if err != nil {
		return sshagent.ReadinessNoAgent, err
	}
	if len(identities) == 0 {
		return sshagent.ReadinessNoKeys, nil
	}
	return sshagent.ReadinessReady, nil
}
