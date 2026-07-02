package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// isolatedShortHome points $HOME at a fresh short-path temp dir so a test's
// control socket (~/.agentjail/run/netproxy-ctl.sock) is isolated from any real
// running netproxy AND stays under the ~104-byte AF_UNIX sun_path limit (macOS
// t.TempDir() lives under /var/folders/... which is too long).
func isolatedShortHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ajsh")
	if err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	return dir
}

// freeAddr returns a currently-free 127.0.0.1 address.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestProxyEnvVars verifies proxyEnvVars carries the session token as the
// Basic-auth username so netproxy can key this session's allowlist.
func TestProxyEnvVars(t *testing.T) {
	tok := proxyctl.Token("abc123")
	vars := proxyEnvVars("127.0.0.1:9100", tok)
	if len(vars) != 3 {
		t.Fatalf("expected 3 env vars, got %d: %v", len(vars), vars)
	}
	wantURL := "http://abc123:@127.0.0.1:9100"
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"} {
		var val string
		for _, v := range vars {
			if strings.HasPrefix(v, key+"=") {
				val = strings.TrimPrefix(v, key+"=")
			}
		}
		if val != wantURL {
			t.Errorf("%s = %q; want %q", key, val, wantURL)
		}
	}
	// The token must be recoverable as the Basic username a client would send.
	enc := base64.StdEncoding.EncodeToString([]byte(string(tok) + ":"))
	if _, err := base64.StdEncoding.DecodeString(enc); err != nil {
		t.Fatalf("token not encodable: %v", err)
	}
}

// TestFindNetproxyBinary_EnvOverride verifies AGENTJAIL_NETPROXY is honored.
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

// TestFindNetproxyBinary_NotFound verifies a clear error when nothing is found.
func TestFindNetproxyBinary_NotFound(t *testing.T) {
	t.Setenv("AGENTJAIL_NETPROXY", "")
	t.Setenv("HOME", t.TempDir())
	if _, err := findNetproxyBinary(); err == nil {
		t.Fatal("expected error when netproxy binary not found")
	}
}

// TestEnsureSessionProxy_StartRegisterEnforce is the end-to-end integration
// test: build netproxy, ensureSessionProxy starts it, registers this session's
// allowlist, and the data plane then enforces that allowlist for a CONNECT that
// carries the returned token.
func TestEnsureSessionProxy_StartRegisterEnforce(t *testing.T) {
	isolatedShortHome(t) // isolate the control socket from any real proxy
	tmpDir := t.TempDir()
	netproxyBin := filepath.Join(tmpDir, "agentjail-netproxy")
	build := exec.Command("go", "build", "-o", netproxyBin, "./cmd/agentjail-netproxy")
	build.Dir = projectRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build netproxy: %v\n%s", err, out)
	}

	proxyAddr := freeAddr(t)
	policy := proxyctl.SessionPolicy{AllowedHosts: []string{"api.github.com"}}

	cmd, tok, err := ensureSessionProxy(netproxyBin, proxyAddr, policy)
	if err != nil {
		t.Fatalf("ensureSessionProxy: %v", err)
	}
	if cmd == nil {
		t.Fatal("expected to have started a fresh proxy (non-nil cmd)")
	}
	t.Cleanup(func() { cleanupNetproxy(cmd) })
	if tok == "" {
		t.Fatal("expected a non-empty session token")
	}

	// A CONNECT carrying the token to a DENIED host must get 403 (proves the
	// registered per-session allowlist is enforced).
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte(string(tok) + ":"))
	fmt.Fprintf(conn, "CONNECT attacker.example.com:443 HTTP/1.1\r\nHost: attacker.example.com\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Errorf("expected 403 for denied host, got: %q", line)
	}

	cleanupNetproxy(cmd)
	if cmd.ProcessState == nil {
		t.Error("cmd.ProcessState is nil after cleanup — process not reaped")
	}
}

// TestEnsureSessionProxy_BinaryNotFound verifies a bogus binary fails closed.
func TestEnsureSessionProxy_BinaryNotFound(t *testing.T) {
	isolatedShortHome(t)
	_, _, err := ensureSessionProxy("/nonexistent/agentjail-netproxy", freeAddr(t), proxyctl.SessionPolicy{})
	if err == nil {
		t.Fatal("expected error starting a nonexistent binary")
	}
}

// TestEnsureSessionProxy_NeverExposesControlSocket verifies a process that
// starts but never exposes a control socket fails closed within the timeout.
func TestEnsureSessionProxy_NeverExposesControlSocket(t *testing.T) {
	isolatedShortHome(t)
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not found; skipping")
	}
	old := proxyStartTimeout
	proxyStartTimeout = 300 * time.Millisecond
	t.Cleanup(func() { proxyStartTimeout = old })

	_, _, err = ensureSessionProxy(sleepBin, freeAddr(t), proxyctl.SessionPolicy{})
	if err == nil {
		t.Fatal("expected error when netproxy never exposes its control socket")
	}
	if !strings.Contains(err.Error(), "control socket") {
		t.Errorf("error should mention the control socket; got: %q", err.Error())
	}
}

// TestCleanupNetproxy_NilSafe verifies cleanupNetproxy tolerates nil/empty cmd
// (the reuse case, where we did not start the proxy).
func TestCleanupNetproxy_NilSafe(t *testing.T) {
	cleanupNetproxy(nil)
	cleanupNetproxy(&exec.Cmd{})
}

// projectRoot returns the repository root by searching upward for go.mod.
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
