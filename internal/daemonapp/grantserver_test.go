package daemonapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
)

// testCtlToken is the injected control token for tests. Injecting it keeps the
// suite off the real ~/.agentjail/control.token.
const testCtlToken = "test-control-token"

type updateAuditEmitter struct {
	events []audit.Event
	err    error
}

func (e *updateAuditEmitter) Emit(_ context.Context, event audit.Event) error {
	e.events = append(e.events, event)
	return e.err
}

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
	gs, err := newGrantServer(ctlSock, testCtlToken, registry, audit.NopEmitter{}, false, nil, nil)
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
	grants, err := grantctl.GrantList(ctlSock, testCtlToken, timeout)
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
	if err := grantctl.GrantDeny(ctlSock, testCtlToken, grantID, timeout); err != nil {
		t.Fatalf("GrantDeny: %v", err)
	}

	// Verify empty
	grants, err = grantctl.GrantList(ctlSock, testCtlToken, timeout)
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
	gs, err := newGrantServer(ctlSock, testCtlToken, registry, audit.NopEmitter{}, false, nil, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	gi, _ := registry.RequestGrant("s1", "/tmp", "api.example.com", 3600000, "", time.Now())
	if err := grantctl.GrantApprove(ctlSock, testCtlToken, gi.GrantID, 3*time.Second); err == nil {
		t.Fatal("expected approve to fail with durableAudit=false")
	}
}

func TestGrantServerE2E_UnboundGrantApproveRejected(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")

	registry := grantctl.NewRegistry()
	// durableAudit=true but grant has no BoundCWD
	gs, err := newGrantServer(ctlSock, testCtlToken, registry, audit.NopEmitter{}, true, nil, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	gi, _ := registry.RequestGrant("s1", "/tmp", "api.example.com", 3600000, "", time.Now())
	// No SetBoundCWD called - grant is unbound
	err = grantctl.GrantApprove(ctlSock, testCtlToken, gi.GrantID, 3*time.Second)
	if err == nil {
		t.Fatal("expected approve to fail for unbound grant")
	}
	// Grant should be rolled back to pending (retryable)
	grants := registry.ListPending(time.Now())
	if len(grants) != 1 {
		t.Errorf("expected grant to be rolled back to pending, got %d", len(grants))
	}
}

func TestGrantServerApprove_ExpiryBoundary(t *testing.T) {
	home := shortTempDir(t)
	t.Setenv("HOME", home)
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(grantctl.PendingGrantTTL)

	t.Run("one nanosecond before expiry persists", func(t *testing.T) {
		project := filepath.Join(home, "live-project")
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		registry := grantctl.NewRegistry()
		grant, err := registry.RequestGrant("s1", project, "api.example.com", 3600000, "", created)
		if err != nil {
			t.Fatal(err)
		}
		registry.SetBoundCWD(grant.GrantID, project)
		emitter := &updateAuditEmitter{}
		gs := &grantServer{registry: registry, emitter: emitter, durableAudit: true}

		if err := gs.approve(grant.GrantID, expires.Add(-time.Nanosecond)); err != nil {
			t.Fatalf("approve before expiry: %v", err)
		}
		overlayPath := filepath.Join(project, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)
		cfg, err := config.Load(overlayPath)
		if err != nil {
			t.Fatalf("load persisted overlay: %v", err)
		}
		if len(cfg.Network.AllowedHosts) != 1 || cfg.Network.AllowedHosts[0] != "api.example.com" {
			t.Fatalf("allowed hosts = %+v", cfg.Network.AllowedHosts)
		}
		if len(emitter.events) != 2 || emitter.events[0].EventType != audit.PolicyChangeRequested || emitter.events[1].EventType != audit.PolicyChanged {
			t.Fatalf("approval audit order = %+v", emitter.events)
		}
	})

	t.Run("at expiry refuses without side effects", func(t *testing.T) {
		project := filepath.Join(home, "expired-project")
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		registry := grantctl.NewRegistry()
		grant, err := registry.RequestGrant("s2", project, "expired.example.com", 3600000, "", created)
		if err != nil {
			t.Fatal(err)
		}
		registry.SetBoundCWD(grant.GrantID, project)
		emitter := &updateAuditEmitter{}
		gs := &grantServer{registry: registry, emitter: emitter, durableAudit: true}

		if err := gs.approve(grant.GrantID, expires); !errors.Is(err, grantctl.ErrGrantExpired) {
			t.Fatalf("approve at expiry = %v, want ErrGrantExpired", err)
		}
		if len(emitter.events) != 0 {
			t.Fatalf("expired approval emitted audit events: %+v", emitter.events)
		}
		overlayPath := filepath.Join(project, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)
		if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
			t.Fatalf("expired approval wrote overlay: %v", err)
		}
		if pending := registry.ListPending(expires); len(pending) != 0 {
			t.Fatalf("expired approval remained pending: %+v", pending)
		}
	})

	t.Run("control response distinguishes expiry", func(t *testing.T) {
		project := filepath.Join(home, "expired-control-project")
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		registry := grantctl.NewRegistry()
		past := time.Now().Add(-grantctl.PendingGrantTTL - time.Second)
		grant, err := registry.RequestGrant("s3", project, "control.example.com", 3600000, "", past)
		if err != nil {
			t.Fatal(err)
		}
		registry.SetBoundCWD(grant.GrantID, project)
		emitter := &updateAuditEmitter{}
		ctlSock := filepath.Join(home, "expired-control.sock")
		gs, err := newGrantServer(ctlSock, testCtlToken, registry, emitter, true, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer gs.close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go gs.serveCtl(ctx)

		err = grantctl.GrantApprove(ctlSock, testCtlToken, grant.GrantID, time.Second)
		if err == nil || err.Error() != "grant approve refused: grant expired" {
			t.Fatalf("expired control refusal = %v", err)
		}
		if len(emitter.events) != 0 {
			t.Fatalf("expired control approval emitted audit events: %+v", emitter.events)
		}
		if _, err := os.Stat(filepath.Join(project, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)); !os.IsNotExist(err) {
			t.Fatalf("expired control approval wrote overlay: %v", err)
		}
	})
}

func TestGrantServerE2E_UpdateAudit(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")
	emitter := &updateAuditEmitter{}
	gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), emitter, false, nil, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.UpdateAudit(ctlSock, testCtlToken, grantctl.UpdateAuditCompleted, "v1.4.0", "linux", time.Second); err != nil {
		t.Fatalf("UpdateAudit: %v", err)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("emitted events = %d, want 1", len(emitter.events))
	}
	event := emitter.events[0]
	if event.EventType != audit.UpdateCompleted || event.Actor != "cli" {
		t.Errorf("event = %+v, want completed CLI update audit", event)
	}
	wantDetail := map[string]string{"version": "v1.4.0", "os": "linux", "status": "completed"}
	if !reflect.DeepEqual(event.Detail, wantDetail) {
		t.Errorf("detail = %#v, want %#v", event.Detail, wantDetail)
	}
}

func TestGrantServerE2E_RegisterSessionLaunch(t *testing.T) {
	tmpDir := shortTempDir(t)
	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")
	emitter := &updateAuditEmitter{}
	activeSessions := newActiveTracker(tmpDir)
	gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), emitter, false, activeSessions, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.RegisterSessionLaunch(ctlSock, testCtlToken, os.Getpid()+100000, tmpDir, "/trusted/bin", time.Second); err == nil {
		t.Fatal("accepted launch PID that did not match the authenticated control peer")
	}
	if err := grantctl.RegisterSessionLaunch(ctlSock, testCtlToken, os.Getpid(), tmpDir, "/trusted/bin", time.Second); err != nil {
		t.Fatalf("RegisterSessionLaunch: %v", err)
	}
	if launch, ok := activeSessions.launches[os.Getpid()]; !ok || launch.Root != tmpDir || launch.Path != "/trusted/bin" {
		t.Fatalf("launch = %+v, %v", launch, ok)
	}
	if len(emitter.events) != 1 || emitter.events[0].EventType != audit.HostProxySessionRegistered {
		t.Fatalf("events = %+v", emitter.events)
	}
	if err := grantctl.UnregisterSessionLaunch(ctlSock, testCtlToken, os.Getpid(), time.Second); err != nil {
		t.Fatalf("UnregisterSessionLaunch: %v", err)
	}
	if _, ok := activeSessions.launches[os.Getpid()]; ok {
		t.Fatal("launch registration survived authenticated shield revocation")
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
	gs, err := newGrantServer(ctlSock, testCtlToken, registry, audit.NopEmitter{}, true, activeSessions, nil)
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

	if err := grantctl.GrantApprove(ctlSock, testCtlToken, gi.GrantID, 3*time.Second); err == nil {
		t.Fatal("expected approve to fail: grant should be unbound because claimed CWD did not verify")
	}

	grants := registry.ListPending(time.Now())
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
			name:         "unverifiable is refused",
			selfReported: "/home/agent/project",
			verified:     "",
			verifyErr:    verifyFailed,
			wantCWD:      "",
			wantOK:       false,
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

func TestDecideBoundCWD_UnverifiableLeavesGrantUnbound(t *testing.T) {
	tmpDir := shortTempDir(t)
	registry := grantctl.NewRegistry()
	grant, err := registry.RequestGrant("s1", tmpDir, "api.example.com", 3600000, "", time.Now())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	if cwd, ok := decideBoundCWD(tmpDir, "", errors.New("simulated resolver failure")); ok || cwd != "" {
		t.Fatalf("decideBoundCWD on resolver failure = (%q, %v), want (\"\", false)", cwd, ok)
	}

	ctlSock := filepath.Join(tmpDir, "daemon-ctl.sock")
	gs, err := newGrantServer(ctlSock, testCtlToken, registry, audit.NopEmitter{}, true, nil, nil)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.GrantApprove(ctlSock, testCtlToken, grant.GrantID, 3*time.Second); err == nil {
		t.Fatal("expected unbound grant approval to fail")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, ".agentjail", "policy.yaml")); !os.IsNotExist(err) {
		t.Fatalf("unverifiable grant wrote an overlay: %v", err)
	}
}
