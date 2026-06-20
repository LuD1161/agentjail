package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProxyEnvVars verifies that proxyEnvVars returns the correct
// HTTPS_PROXY, HTTP_PROXY, and ALL_PROXY environment variables.
func TestProxyEnvVars(t *testing.T) {
	vars := proxyEnvVars("127.0.0.1:9100")
	if len(vars) != 3 {
		t.Fatalf("expected 3 env vars, got %d: %v", len(vars), vars)
	}
	expected := map[string]string{
		"HTTPS_PROXY": "http://127.0.0.1:9100",
		"HTTP_PROXY":  "http://127.0.0.1:9100",
		"ALL_PROXY":   "http://127.0.0.1:9100",
	}
	for _, v := range vars {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			t.Errorf("malformed env var: %q", v)
			continue
		}
		key, val := parts[0], parts[1]
		want, ok := expected[key]
		if !ok {
			t.Errorf("unexpected env var key: %q", key)
			continue
		}
		if val != want {
			t.Errorf("%s = %q; want %q", key, val, want)
		}
	}
}

// TestFindNetproxyBinary_EnvOverride verifies that findNetproxyBinary
// respects the AGENTJAIL_NETPROXY environment variable.
func TestFindNetproxyBinary_EnvOverride(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-netproxy")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	t.Setenv("AGENTJAIL_NETPROXY", fakeBin)
	got, err := findNetproxyBinary()
	if err != nil {
		t.Fatalf("findNetproxyBinary: %v", err)
	}
	if got != fakeBin {
		t.Errorf("findNetproxyBinary = %q; want %q", got, fakeBin)
	}
}

// TestFindNetproxyBinary_NotFound verifies that findNetproxyBinary returns
// an error when the binary cannot be found.
func TestFindNetproxyBinary_NotFound(t *testing.T) {
	t.Setenv("AGENTJAIL_NETPROXY", "")
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, err := findNetproxyBinary()
	if err == nil {
		t.Fatal("expected error when netproxy binary not found")
	}
}

// TestNetproxyStartAndCleanup is an integration test that builds the
// agentjail-netproxy binary, starts it via startNetproxy, verifies it
// enforces the allowlist, and cleans it up via cleanupNetproxy.
//
// This test verifies the Linux netproxy integration (P2.2): the shield
// can start netproxy as a child, the proxy enforces network.allowed_hosts,
// and the proxy child is properly reaped on cleanup.
func TestNetproxyStartAndCleanup(t *testing.T) {
	// Build the netproxy binary to a temp location.
	tmpDir := t.TempDir()
	netproxyBin := filepath.Join(tmpDir, "agentjail-netproxy")
	buildCmd := exec.Command("go", "build", "-o", netproxyBin, "./cmd/agentjail-netproxy")
	buildCmd.Dir = projectRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build netproxy: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(netproxyBin) })

	// Write a policy file that allows only "api.github.com".
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	policyContent := "network:\n  allowed_hosts:\n    - api.github.com\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Use a random port to avoid conflicts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxyAddr := ln.Addr().String()
	ln.Close()

	// Start the netproxy.
	cmd, err := startNetproxy(netproxyBin, proxyAddr, policyFile)
	if err != nil {
		t.Fatalf("startNetproxy: %v", err)
	}

	// Verify the proxy is running by sending a CONNECT to a denied host.
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT attacker.example.com:443 HTTP/1.1\r\nHost: attacker.example.com\r\n\r\n")

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Errorf("expected 403 for denied host, got: %q", line)
	}

	// Clean up the netproxy child (zombie cleanup).
	cleanupNetproxy(cmd)

	// Verify the process is no longer running.
	if cmd.ProcessState == nil {
		t.Error("cmd.ProcessState is nil after cleanup — process not reaped")
	}
}

// TestCleanupNetproxy_NilSafe verifies that cleanupNetproxy does not panic
// when called with a nil cmd.
func TestCleanupNetproxy_NilSafe(t *testing.T) {
	cleanupNetproxy(nil)
	cleanupNetproxy(&exec.Cmd{})
}

// projectRoot returns the repository root directory by searching upward
// from the test binary's location for a go.mod file.
func projectRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			t.Fatal("could not find go.mod")
		}
		cwd = parent
	}
}

// TestStartNetproxyBindTimeout verifies that startNetproxy returns an error
// when the proxy fails to bind within the timeout.  We start a process that
// does nothing (sleep) so the proxy never binds.
func TestStartNetproxyBindTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a fake "binary" that just sleeps (never binds).
	fakeBin := filepath.Join(tmpDir, "fake-proxy")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nsleep 10\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, startErr := startNetproxy(fakeBin, addr, "/dev/null")
	if startErr == nil {
		t.Fatal("expected error when proxy fails to bind")
	}

	time.Sleep(100 * time.Millisecond)
}
