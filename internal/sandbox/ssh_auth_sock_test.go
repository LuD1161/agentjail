//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package sandbox

import (
	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSSHAuthSocket(t *testing.T) string {
	t.Helper()
	// Keep the socket short and free of symlink components on macOS.
	tempRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	dir, err := os.MkdirTemp(tempRoot, "ajssh")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return path
}

func TestValidateSSHAuthSockAcceptsOwnedUnixSocket(t *testing.T) {
	path := testSSHAuthSocket(t)
	got, err := ValidateSSHAuthSock(path, SSHAuthSockPolicy{})
	if err != nil {
		t.Fatalf("ValidateSSHAuthSock: %v", err)
	}
	if got.Path != path {
		t.Fatalf("path = %q, want %q", got.Path, path)
	}
}

func TestValidateSSHAuthSockRejectsMalformedAndUntrustedPaths(t *testing.T) {
	path := testSSHAuthSocket(t)
	link := filepath.Join(t.TempDir(), "socket-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		path   string
		policy SSHAuthSockPolicy
	}{
		{"relative", "agent.sock", SSHAuthSockPolicy{}},
		{"unclean", filepath.Dir(path) + "/./agent.sock", SSHAuthSockPolicy{}},
		{"control character", path + "\n", SSHAuthSockPolicy{}},
		{"regular file", filepath.Join(t.TempDir(), "not-a-socket"), SSHAuthSockPolicy{}},
		{"symlink", link, SSHAuthSockPolicy{}},
		{"shield control directory", path, SSHAuthSockPolicy{ForbiddenDirs: []string{filepath.Dir(path)}}},
	}
	if err := os.WriteFile(cases[3].path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateSSHAuthSock(tc.path, tc.policy)
			if err == nil || got.Path != "" {
				t.Fatalf("got %#v, %v; want rejection", got, err)
			}
		})
	}
}

func TestAppendSSHAuthSockOnlyUsesValidatedValue(t *testing.T) {
	env := []string{"PATH=/usr/bin"}
	if got := AppendSSHAuthSock(env, SSHAuthSock{}); strings.Join(got, ",") != "PATH=/usr/bin" {
		t.Fatalf("zero socket changed environment: %v", got)
	}
	path := testSSHAuthSocket(t)
	got := AppendSSHAuthSock(env, SSHAuthSock{Path: path})
	if !strings.Contains(strings.Join(got, ","), "SSH_AUTH_SOCK="+path) {
		t.Fatalf("validated socket missing from %v", got)
	}
}

func TestReplaceSSHAgentEnvOverridesPolicyPassthrough(t *testing.T) {
	strip := true
	cfg := &config.PolicyConfig{Secrets: config.SecretsConfig{
		StripOnLaunch:  &strip,
		EnvPassthrough: []string{"SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE", "AGENTJAIL_SSH_AGENT_DELEGATED"},
	}}
	env := StripEnv(BuildCleanEnv([]string{
		"SSH_AUTH_SOCK=/tmp/ambient.sock",
		"GIT_SSH_COMMAND=ssh -F /tmp/ambient-config",
		"AGENTJAIL_SSH_OVERRIDE=1",
		"AGENTJAIL_SSH_AGENT_DELEGATED=1",
	}, cfg), cfg)
	got := ReplaceSSHAgentEnv(env, SSHAuthSock{}, "AGENTJAIL_SSH_AGENT_DELEGATED")
	for _, kv := range got {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") || strings.HasPrefix(kv, "GIT_SSH_COMMAND=") || strings.HasPrefix(kv, "AGENTJAIL_SSH_OVERRIDE=") || strings.HasPrefix(kv, "AGENTJAIL_SSH_AGENT_DELEGATED=") {
			t.Fatalf("ambient SSH authority survived policy passthrough: %v", got)
		}
	}
}
