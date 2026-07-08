package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

// shortTempDir returns a short-lived temp directory whose path stays well
// under the ~104-byte sockaddr_un limit (unlike t.TempDir(), which embeds the
// full test name and can overflow it on macOS/BSD).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestGrantServerE2E_RequestListDeny(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")
	reqSock := filepath.Join(tmpDir, "daemon.sock")

	registry := grantctl.NewRegistry()
	gs, err := newGrantServer(ctlSock, registry, audit.NopEmitter{}, false, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	// Simulate daemon.sock request listener
	reqLn, err := net.Listen("unix", reqSock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer reqLn.Close()
	go func() {
		for {
			conn, err := reqLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req grantctl.Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				resp := gs.handleGrantRequest(conn, req)
				json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()

	timeout := 3 * time.Second

	// File a grant request
	grantID, err := grantctl.GrantRequest(reqSock, "test-session", "/tmp/repo", "api.example.com", 3600000, "test reason", timeout)
	if err != nil {
		t.Fatalf("GrantRequest: %v", err)
	}
	if grantID == "" {
		t.Fatal("expected non-empty grant_id")
	}

	// List grants
	grants, err := grantctl.GrantList(ctlSock, timeout)
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(grants))
	}
	if grants[0].Host != "api.example.com" {
		t.Errorf("host = %q, want api.example.com", grants[0].Host)
	}

	// Deny
	if err := grantctl.GrantDeny(ctlSock, grantID, timeout); err != nil {
		t.Fatalf("GrantDeny: %v", err)
	}

	// Verify empty
	grants, err = grantctl.GrantList(ctlSock, timeout)
	if err != nil {
		t.Fatalf("GrantList after deny: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("expected 0 after deny, got %d", len(grants))
	}
}

func TestGrantServerE2E_ApproveDeniedWithoutAudit(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")

	registry := grantctl.NewRegistry()
	// durableAudit=false
	gs, err := newGrantServer(ctlSock, registry, audit.NopEmitter{}, false, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	gi, _ := registry.RequestGrant("s1", "/tmp", "api.example.com", 3600000, "", time.Now())
	if err := grantctl.GrantApprove(ctlSock, gi.GrantID, 3*time.Second); err == nil {
		t.Fatal("expected approve to fail with durableAudit=false")
	}
}

func TestGrantServerE2E_UnboundGrantApproveRejected(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")

	registry := grantctl.NewRegistry()
	// durableAudit=true but grant has no BoundCWD
	gs, err := newGrantServer(ctlSock, registry, audit.NopEmitter{}, true, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	gi, _ := registry.RequestGrant("s1", "/tmp", "api.example.com", 3600000, "", time.Now())
	// No SetBoundCWD called - grant is unbound
	err = grantctl.GrantApprove(ctlSock, gi.GrantID, 3*time.Second)
	if err == nil {
		t.Fatal("expected approve to fail for unbound grant")
	}
	// Grant should be rolled back to pending (retryable)
	grants := registry.ListPending()
	if len(grants) != 1 {
		t.Errorf("expected grant to be rolled back to pending, got %d", len(grants))
	}
}

// TestHandleGrantRequest_CWDMismatchLeavesGrantUnbound is an end-to-end P10
// regression test: a grant_request whose session-tracked (self-reported)
// CWD does not match the connecting process's real, kernel-verified CWD
// (read from /proc/<pid>/cwd) must NOT be bound to that self-reported
// directory. approve() refuses to persist an unbound grant
// (errGrantUnbound), so the observable effect is "approve fails, grant
// stays pending" rather than a policy.yaml overlay landing wherever the
// agent claimed to be.
func TestHandleGrantRequest_CWDMismatchLeavesGrantUnbound(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")

	registry := grantctl.NewRegistry()
	activeSessions := newActiveTracker(tmpDir)
	// Track a session whose PID is this test process's own PID (so
	// extractPeerPID(conn) — driven by the real Unix socket connection
	// below — resolves to a PID activeSessions recognizes) but whose CWD is
	// a directory this process is definitely NOT actually running in.
	activeSessions.update("s1", os.Getpid(), "/definitely/not/the/real/cwd")

	// durableAudit=true so the ONLY reason approve can fail is the unbound
	// grant, isolating the CWD-mismatch behavior from the audit-gate
	// behavior already covered by TestGrantServerE2E_ApproveDeniedWithoutAudit.
	gs, err := newGrantServer(ctlSock, registry, audit.NopEmitter{}, true, activeSessions)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	// handleGrantRequest reads the peer PID off conn via SO_PEERCRED, so it
	// must be driven over a real Unix domain socket connection (not a plain
	// io.Pipe) with THIS process on the other end.
	reqSock := filepath.Join(tmpDir, "daemon.sock")
	reqLn, err := net.Listen("unix", reqSock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer reqLn.Close()

	var gi grantctl.Response
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := reqLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		gi = gs.handleGrantRequest(conn, grantctl.Request{
			SessionID: "s1",
			CWD:       "/definitely/not/the/real/cwd",
			Host:      "api.example.com",
			TTLMs:     3600000,
		})
	}()

	client, err := net.Dial("unix", reqSock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	<-done

	if !gi.OK {
		t.Fatalf("handleGrantRequest failed: %s", gi.Error)
	}

	if err := grantctl.GrantApprove(ctlSock, gi.GrantID, 3*time.Second); err == nil {
		t.Fatal("expected approve to fail: grant should be unbound because claimed CWD did not verify")
	}

	grants := registry.ListPending()
	if len(grants) != 1 {
		t.Errorf("expected grant to remain pending (unbound, not applied), got %d pending", len(grants))
	}

	// No overlay should have been written anywhere under the claimed
	// (unverified) directory.
	if _, err := os.Stat(filepath.Join("/definitely/not/the/real/cwd", ".agentjail", "policy.yaml")); err == nil {
		t.Fatal("overlay was written into the unverified claimed CWD — P10 regression")
	}
}

// TestDecideBoundCWD covers the P10 CWD-verification decision in isolation,
// using faked self-reported/verified CWD values and a faked verification
// error -- no real PID or /proc access needed.
func TestDecideBoundCWD(t *testing.T) {
	verifyFailed := errors.New("simulated resolvePeerCWD failure")

	cases := []struct {
		name         string
		selfReported string
		verified     string
		verifyErr    error
		wantCWD      string
		wantOK       bool
	}{
		{
			name:         "verified match is trusted",
			selfReported: "/home/agent/project",
			verified:     "/home/agent/project",
			verifyErr:    nil,
			wantCWD:      "/home/agent/project",
			wantOK:       true,
		},
		{
			name:         "verified mismatch is refused",
			selfReported: "/home/agent/project",
			verified:     "/tmp/somewhere-else",
			verifyErr:    nil,
			wantCWD:      "",
			wantOK:       false,
		},
		{
			name:         "empty verified CWD is refused even without an error",
			selfReported: "/home/agent/project",
			verified:     "",
			verifyErr:    nil,
			wantCWD:      "",
			wantOK:       false,
		},
		{
			name:         "unverifiable falls back to self-reported",
			selfReported: "/home/agent/project",
			verified:     "",
			verifyErr:    verifyFailed,
			wantCWD:      "/home/agent/project",
			wantOK:       true,
		},
		{
			name:         "unverifiable with empty self-reported CWD is refused",
			selfReported: "",
			verified:     "",
			verifyErr:    verifyFailed,
			wantCWD:      "",
			wantOK:       false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCWD, gotOK := decideBoundCWD(tc.selfReported, tc.verified, tc.verifyErr)
			if gotCWD != tc.wantCWD || gotOK != tc.wantOK {
				t.Errorf("decideBoundCWD(%q, %q, %v) = (%q, %v), want (%q, %v)",
					tc.selfReported, tc.verified, tc.verifyErr, gotCWD, gotOK, tc.wantCWD, tc.wantOK)
			}
		})
	}
}
