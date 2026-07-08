package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// startStubDaemonAt is like stubDaemon but binds at an exact caller-supplied
// path instead of generating one, so tests can control whether the path
// lands inside or outside the trusted ~/.agentjail directory.
func startStubDaemonAt(t *testing.T, sockPath string, actionFn func(req daemonRequest) (string, string, string)) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("stub listen at %s: %v", sockPath, err)
	}

	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			return
		}
		var req daemonRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return
		}

		action, reason, ruleID := actionFn(req)
		resp := daemonResponse{
			ID:     req.ID,
			Action: action,
			Reason: reason,
			RuleID: ruleID,
		}
		enc := json.NewEncoder(conn)
		_ = enc.Encode(resp)
	}()
}

// mustDecode unmarshals b into v, failing the test on error.
func mustDecode(t *testing.T, b []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
}

// TestIsTrustedSocketOverride is a table test for the AGENTJAIL_SOCKET
// trust-boundary check: an override is only honored when it resolves under
// the trusted ~/.agentjail state directory. Before this check,
// AGENTJAIL_SOCKET was honored unconditionally, so an attacker-supplied
// value reaching the hook's env pointed it at an arbitrary always-allow
// socket.
func TestIsTrustedSocketOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	trustedDir := filepath.Join(home, ".agentjail")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"empty", "", false},
		{"evil absolute path outside trusted dir", "/tmp/evil.sock", false},
		{"evil path in sibling dir with similar prefix", home + "-evil/daemon.sock", false},
		{"exact trusted dir daemon.sock", filepath.Join(trustedDir, "daemon.sock"), true},
		{"nested under trusted dir", filepath.Join(trustedDir, "sockets", "alt.sock"), true},
		{"path traversal back out of trusted dir", filepath.Join(trustedDir, "..", "evil.sock"), false},
		{"trusted dir itself, no filename", trustedDir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTrustedSocketOverride(tt.path)
			if got != tt.want {
				t.Errorf("isTrustedSocketOverride(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestResolveSocketPath verifies the end-to-end selection logic: unset falls
// back to the default path, an untrusted override is ignored (falls back to
// default), and a trusted override (under $HOME/.agentjail) is honored.
func TestResolveSocketPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	trustedDir := filepath.Join(home, ".agentjail")
	def := defaultSocketPath()

	t.Run("unset uses default", func(t *testing.T) {
		t.Setenv("AGENTJAIL_SOCKET", "")
		if got := resolveSocketPath(); got != def {
			t.Errorf("resolveSocketPath() = %q, want default %q", got, def)
		}
	})

	t.Run("untrusted override ignored, falls back to default", func(t *testing.T) {
		t.Setenv("AGENTJAIL_SOCKET", "/tmp/evil.sock")
		if got := resolveSocketPath(); got != def {
			t.Errorf("resolveSocketPath() = %q, want default %q (evil override must be ignored)", got, def)
		}
	})

	t.Run("trusted override honored", func(t *testing.T) {
		override := filepath.Join(trustedDir, "alt-daemon.sock")
		t.Setenv("AGENTJAIL_SOCKET", override)
		if got := resolveSocketPath(); got != override {
			t.Errorf("resolveSocketPath() = %q, want honored override %q", got, override)
		}
	})
}

// TestHook_SocketOverride_EvilPathIgnored is an end-to-end check: a daemon
// stub is bound at the default (trusted) socket path, AGENTJAIL_SOCKET is set
// to an untrusted path with no listener behind it, and the hook must still
// reach the stub daemon at the default path (an "allow" response) rather
// than failing open because it tried to dial the untrusted path.
func TestHook_SocketOverride_EvilPathIgnored(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	agentjailDir := trustedHome(t)
	defaultSock := filepath.Join(agentjailDir, "daemon.sock")

	startStubDaemonAt(t, defaultSock, func(req daemonRequest) (string, string, string) {
		return "allow", "reached the real daemon", "default"
	})

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/hello.txt",
		"content": "hello",
	}, "session-evil-socket")

	evilSock := "/tmp/agentjail-evil-always-allow.sock"
	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + evilSock})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", code, stderr)
	}
	var out claudeHookOutput
	mustDecode(t, stdout, &out)
	if out.HookSpecificOutput.PermissionDecisionReason != "reached the real daemon" {
		t.Errorf("permissionDecisionReason = %q, want the stub daemon's reason (evil socket must be ignored, default used instead); stderr=%q",
			out.HookSpecificOutput.PermissionDecisionReason, stderr)
	}
}

// TestHook_SocketOverride_TrustedPathHonored verifies the converse: an
// override under the trusted ~/.agentjail directory is honored even though
// it does not match the conventional "daemon.sock" filename.
func TestHook_SocketOverride_TrustedPathHonored(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	agentjailDir := trustedHome(t)
	altSock := filepath.Join(agentjailDir, "alt-daemon.sock")

	startStubDaemonAt(t, altSock, func(req daemonRequest) (string, string, string) {
		return "allow", "reached the trusted override", "default"
	})

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/hello.txt",
		"content": "hello",
	}, "session-trusted-socket")

	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + altSock})

	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", code, stderr)
	}
	var out claudeHookOutput
	mustDecode(t, stdout, &out)
	if out.HookSpecificOutput.PermissionDecisionReason != "reached the trusted override" {
		t.Errorf("permissionDecisionReason = %q, want the stub daemon's reason (trusted override must be honored)",
			out.HookSpecificOutput.PermissionDecisionReason)
	}
}
