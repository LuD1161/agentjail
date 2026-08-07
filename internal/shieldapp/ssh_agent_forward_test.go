package shieldapp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Keep fixtures short and canonical: macOS's /var temp path is a symlink, and
// SSH-agent validation rejects symlink components.
func shieldTestShortSocketDir(t *testing.T) string {
	t.Helper()
	tempRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	dir, err := os.MkdirTemp(tempRoot, "ajssh")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func shieldTestSSHSocket(t *testing.T) string {
	t.Helper()
	path := filepath.Join(shieldTestShortSocketDir(t), "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request := make([]byte, 5)
		if _, err := io.ReadFull(conn, request); err != nil || request[4] != 11 {
			return
		}
		// SSH2_AGENT_IDENTITIES_ANSWER with zero loaded identities.
		response := []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}
		_, _ = conn.Write(response)
	}()
	return path
}

func TestSelectSSHAgentForwardingDisabled(t *testing.T) {
	got, err := selectSSHAgentForwarding(false, "/not/a/socket", t.TempDir())
	if err != nil || got.Path != "" {
		t.Fatalf("default forwarding = %#v, %v; want no capability", got, err)
	}
}

func TestResolveGitSSHLaunchMode(t *testing.T) {
	tests := []struct {
		name            string
		policy, on, off bool
		want            gitSSHLaunchMode
		wantErr         bool
	}{
		{"standard policy", true, false, false, gitSSHAutomatic, false},
		{"strict policy", false, false, false, gitSSHDisabled, false},
		{"explicit enable", false, true, false, gitSSHExplicit, false},
		{"per-launch disable", true, false, true, gitSSHDisabled, false},
		{"conflict", true, true, true, gitSSHDisabled, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveGitSSHLaunchMode(tc.policy, tc.on, tc.off)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("mode = %v, err = %v; want %v, err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestSelectSSHAgentForwardingRejectsNonAgentListener(t *testing.T) {
	path := filepath.Join(shieldTestShortSocketDir(t), "not-agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	got, err := selectSSHAgentForwarding(true, path, t.TempDir())
	if err == nil || got.Path != "" {
		t.Fatalf("non-agent listener accepted: %#v, %v", got, err)
	}
}

func TestSelectSSHAgentForwardingExplicitValidSocket(t *testing.T) {
	path := shieldTestSSHSocket(t)
	got, err := selectSSHAgentForwarding(true, path, t.TempDir())
	if err != nil || got.Path != path {
		t.Fatalf("explicit forwarding = %#v, %v; want %q", got, err, path)
	}
}

func TestSelectSSHAgentForwardingFailsClosed(t *testing.T) {
	path := shieldTestSSHSocket(t)
	link := filepath.Join(t.TempDir(), "socket-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	home := shieldTestShortSocketDir(t)
	controlDir := filepath.Join(home, ".agentjail")
	if err := os.Mkdir(controlDir, 0o700); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(controlDir, "daemon.sock")
	controlListener, err := net.Listen("unix", control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controlListener.Close() })
	regular := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing", ""},
		{"relative", "agent.sock"},
		{"regular", regular},
		{"symlink", link},
		{"shield control socket", control},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectSSHAgentForwarding(true, tc.path, home)
			if err == nil || got.Path != "" {
				t.Fatalf("got %#v, %v; want fail-closed rejection", got, err)
			}
		})
	}
}
