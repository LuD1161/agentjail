package main

import (
	"context"
	"encoding/json"
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
