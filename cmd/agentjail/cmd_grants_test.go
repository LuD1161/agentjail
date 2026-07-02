package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// fakeControlSocket is a minimal stand-in for netproxy's control plane
// (internal/proxyctl wire protocol) so grant/grants commands can be tested
// end-to-end without a real netproxy. It binds at the exact path
// proxyctl.ControlSocketPath() resolves to for the given home dir, so the
// commands under test (which hardcode proxyctl.ControlSocketPath()) find it
// via $HOME alone.
type fakeControlSocket struct {
	pending map[string]proxyctl.GrantInfo
}

// shortHomeDir returns a fresh temp directory short enough to hold a
// AF_UNIX socket under it (sun_path is capped at ~104-108 bytes). t.TempDir()
// alone is often too deep (e.g. under macOS's $TMPDIR), so this allocates
// directly under /tmp instead.
func shortHomeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ajgrant")
	if err != nil {
		t.Fatalf("create short temp home dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func startFakeControlSocket(t *testing.T, home string, grants []proxyctl.GrantInfo) *fakeControlSocket {
	t.Helper()
	dir := proxyctl.ControlSocketDirForHome(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir control socket dir: %v", err)
	}
	sockPath := proxyctl.ControlSocketPathForHome(home)

	f := &fakeControlSocket{pending: make(map[string]proxyctl.GrantInfo)}
	for _, g := range grants {
		f.pending[g.GrantID] = g
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on fake control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeControlSocket) serve(conn net.Conn) {
	defer conn.Close()
	var req proxyctl.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	var resp proxyctl.Response
	switch req.Type {
	case proxyctl.ReqGrantList:
		list := make([]proxyctl.GrantInfo, 0, len(f.pending))
		for _, g := range f.pending {
			list = append(list, g)
		}
		resp = proxyctl.Response{OK: true, Grants: list}
	case proxyctl.ReqGrantApprove:
		if _, ok := f.pending[req.GrantID]; ok {
			delete(f.pending, req.GrantID)
			resp = proxyctl.Response{OK: true}
		} else {
			resp = proxyctl.Response{OK: false, Error: "unknown grant_id"}
		}
	case proxyctl.ReqGrantDeny:
		if _, ok := f.pending[req.GrantID]; ok {
			delete(f.pending, req.GrantID)
			resp = proxyctl.Response{OK: true}
		} else {
			resp = proxyctl.Response{OK: false, Error: "unknown grant_id"}
		}
	default:
		resp = proxyctl.Response{OK: false, Error: "unsupported request type in fake control socket"}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func TestRunGrantsList_NoPending(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeControlSocket(t, home, nil)

	stdout, stderr, code := captureOutput(t, runGrantsList)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "no pending grant requests") {
		t.Errorf("stdout = %q, want a no-pending message", stdout)
	}
}

func TestRunGrantsList_ListsPending(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeControlSocket(t, home, []proxyctl.GrantInfo{
		{GrantID: "g-1", Host: "api.example.com", TTLMs: 3600000, Cwd: "/repo/one", Reason: "need it"},
	})

	stdout, stderr, code := captureOutput(t, runGrantsList)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	for _, want := range []string{"g-1", "api.example.com", "/repo/one", "need it"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunGrantsList_NoNetproxyRunning(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	// No fake control socket started -- ControlSocketPath() resolves under
	// an empty temp $HOME, so the dial must fail.

	_, stderr, code := captureOutput(t, runGrantsList)
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when no netproxy control socket exists")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestRunGrantDeny(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeControlSocket(t, home, []proxyctl.GrantInfo{
		{GrantID: "g-deny", Host: "deny.example.com", TTLMs: 60000},
	})

	stdout, stderr, code := captureOutput(t, func() int {
		return runGrantDeny("g-deny")
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "denied") {
		t.Errorf("stdout = %q, want a denied confirmation", stdout)
	}
}

func TestRunGrantDeny_UnknownID(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeControlSocket(t, home, nil)

	_, stderr, code := captureOutput(t, func() int {
		return runGrantDeny("does-not-exist")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an unknown grant_id")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestRunGrantApprove_WithoutPersist(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeControlSocket(t, home, []proxyctl.GrantInfo{
		{GrantID: "g-approve", Host: "approve.example.com", TTLMs: 60000},
	})

	stdout, stderr, code := captureOutput(t, func() int {
		return runGrantApprove("g-approve", false, "")
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "granted") {
		t.Errorf("stdout = %q, want a granted confirmation", stdout)
	}
}

func TestRunGrantApprove_WithPersist_MergesOverlayAndTrust(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	repoDir := t.TempDir()
	startFakeControlSocket(t, home, []proxyctl.GrantInfo{
		{GrantID: "g-persist", Host: "widened.example.com", TTLMs: 3600000, Cwd: repoDir, Reason: "ci needs it"},
	})

	stdout, stderr, code := captureOutput(t, func() int {
		return runGrantApprove("g-persist", true, repoDir)
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "granted") {
		t.Errorf("stdout missing granted confirmation: %q", stdout)
	}
	if !strings.Contains(stdout, "persisted") {
		t.Errorf("stdout missing persist confirmation: %q", stdout)
	}

	overlayPath := filepath.Join(repoDir, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)
	cfg, err := config.Load(overlayPath)
	if err != nil {
		t.Fatalf("load persisted overlay: %v", err)
	}
	found := false
	for _, h := range cfg.Network.AllowedHosts {
		if h == "widened.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("overlay allowed_hosts = %v, want widened.example.com present", cfg.Network.AllowedHosts)
	}

	trustPath := projectpolicy.TrustStorePath(filepath.Join(home, projectpolicy.ProjectDirName))
	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	data, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	o := &projectpolicy.Overlay{Path: overlayPath, ContentHash: projectpolicy.HashContent(data)}
	if !ts.IsTrusted(o) {
		t.Error("persisted overlay must be trusted after --persist")
	}
}

func TestRunGrantApprove_PersistFailsAfterUnknownGrantID(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	repoDir := t.TempDir()
	startFakeControlSocket(t, home, nil) // nothing pending

	_, stderr, code := captureOutput(t, func() int {
		return runGrantApprove("does-not-exist", true, repoDir)
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when the grant_id to persist cannot be found")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
	// Nothing should have been written since the host was never resolved.
	overlayPath := filepath.Join(repoDir, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)
	if _, err := os.Stat(overlayPath); err == nil {
		t.Error("overlay must not be created when the grant lookup fails before approve")
	}
}

func TestPersistGrantHost_CreatesOverlayAndIsIdempotent(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	repoDir := t.TempDir()

	overlayPath, err := persistGrantHost(repoDir, "db.internal.example.com")
	if err != nil {
		t.Fatalf("persistGrantHost: %v", err)
	}
	wantPath := filepath.Join(repoDir, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)
	if overlayPath != wantPath {
		t.Errorf("overlayPath = %q, want %q", overlayPath, wantPath)
	}

	cfg, err := config.Load(overlayPath)
	if err != nil {
		t.Fatalf("load overlay: %v", err)
	}
	if len(cfg.Network.AllowedHosts) != 1 || cfg.Network.AllowedHosts[0] != "db.internal.example.com" {
		t.Fatalf("allowed_hosts = %v, want exactly [db.internal.example.com]", cfg.Network.AllowedHosts)
	}

	// Calling again with the same host must not duplicate it.
	if _, err := persistGrantHost(repoDir, "db.internal.example.com"); err != nil {
		t.Fatalf("persistGrantHost (second call): %v", err)
	}
	cfg2, err := config.Load(overlayPath)
	if err != nil {
		t.Fatalf("load overlay after second persist: %v", err)
	}
	count := 0
	for _, h := range cfg2.Network.AllowedHosts {
		if h == "db.internal.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("db.internal.example.com appears %d times, want 1 (persist must be idempotent)", count)
	}
}

func TestPersistGrantHost_PreservesExistingOverlayContent(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	repoDir := t.TempDir()
	overlayDir := filepath.Join(repoDir, projectpolicy.ProjectDirName)
	if err := os.MkdirAll(overlayDir, 0o755); err != nil {
		t.Fatalf("mkdir overlay dir: %v", err)
	}
	overlayPath := filepath.Join(overlayDir, projectpolicy.ProjectPolicyFile)
	existing := &config.PolicyConfig{}
	existing.Network.AllowedHosts = []string{"already-here.example.com"}
	existing.MCP.Allowed = []string{"filesystem"}
	if err := config.Save(existing, overlayPath); err != nil {
		t.Fatalf("seed overlay: %v", err)
	}

	if _, err := persistGrantHost(repoDir, "new-host.example.com"); err != nil {
		t.Fatalf("persistGrantHost: %v", err)
	}

	cfg, err := config.Load(overlayPath)
	if err != nil {
		t.Fatalf("load overlay: %v", err)
	}
	wantHosts := map[string]bool{"already-here.example.com": true, "new-host.example.com": true}
	for _, h := range cfg.Network.AllowedHosts {
		delete(wantHosts, h)
	}
	if len(wantHosts) != 0 {
		t.Errorf("overlay lost or missing hosts: %v; got %v", wantHosts, cfg.Network.AllowedHosts)
	}
	if len(cfg.MCP.Allowed) != 1 || cfg.MCP.Allowed[0] != "filesystem" {
		t.Errorf("overlay lost unrelated mcp.allowed content: %v", cfg.MCP.Allowed)
	}
}
