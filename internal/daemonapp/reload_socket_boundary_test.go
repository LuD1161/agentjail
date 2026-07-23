package daemonapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

// TestDaemonReload_ServedOnControlSocket: the privileged socket serves reload.
func TestDaemonReload_ServedOnControlSocket(t *testing.T) {
	ctlSock := filepath.Join(shortSockDir(t), "ctl.sock")

	var called atomic.Int32
	gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil, nil,
		func(context.Context) error { called.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.DaemonReload(ctlSock, testCtlToken, 2*time.Second); err != nil {
		t.Fatalf("reload over the control socket should succeed: %v", err)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("expected exactly one reload, got %d", got)
	}
}

// TestCtlSocket_RequiresCtlToken is the ADR 0069 regression: a caller that can
// reach daemon-ctl.sock but cannot read ~/.agentjail/control.token gets nothing.
// That is exactly the sandboxed agent's position on Linux, where Landlock permits
// the connect() and the same-UID peer check passes (ADR 0069).
//
// reload is the one that matters most: it is a full Rego recompile, so an
// unauthenticated caller could spend the daemon's CPU on demand while the hook's
// ~30ms budget fails open.
func TestCtlSocket_RequiresCtlToken(t *testing.T) {
	for _, tc := range []struct{ name, token string }{
		{"missing", ""},
		{"wrong", "not-the-token"},
		{"prefix", testCtlToken[:len(testCtlToken)-1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctlSock := filepath.Join(shortSockDir(t), "ctl.sock")

			var reloads atomic.Int32
			gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), audit.NopEmitter{}, true, nil, nil,
				func(context.Context) error { reloads.Add(1); return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer gs.close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go gs.serveCtl(ctx)

			for _, req := range []grantctl.Request{
				{Type: grantctl.ReqDaemonReload},
				{Type: grantctl.ReqGrantList},
				{Type: grantctl.ReqGrantApprove, GrantID: "g1"},
				{Type: grantctl.ReqGrantDeny, GrantID: "g1"},
			} {
				req.CtlToken = tc.token
				resp := rawCtlRoundTrip(t, ctlSock, req)
				if resp.OK {
					t.Errorf("%s with a %s token was accepted; want unauthorized", req.Type, tc.name)
				}
				if resp.Error != "unauthorized" {
					t.Errorf("%s error = %q; want %q", req.Type, resp.Error, "unauthorized")
				}
				if resp.Grants != nil {
					t.Errorf("unauthorized %s leaked grants: %+v", req.Type, resp.Grants)
				}
			}
			// The rejection must precede the work, not just the reply.
			if got := reloads.Load(); got != 0 {
				t.Errorf("unauthorized reload still recompiled %d time(s); the DoS lever is open", got)
			}
		})
	}
}

// rawCtlRoundTrip sends req verbatim, with no token defaulting, so auth tests
// can express "sent nothing".
func rawCtlRoundTrip(t *testing.T, sock string, req grantctl.Request) grantctl.Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial control socket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp grantctl.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// TestDaemonReload_CompileFailureIsRefusedNotTransport: a rejected policy must
// surface as *RefusedError carrying the compile error, so the CLI reports "your
// policy did not take effect" instead of falling back to SIGHUP and reporting
// success against the still-loaded old bundle.
func TestDaemonReload_CompileFailureIsRefusedNotTransport(t *testing.T) {
	ctlSock := filepath.Join(shortSockDir(t), "ctl.sock")

	gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil, nil,
		func(context.Context) error { return errors.New("reload: compile: rego parse error") })
	if err != nil {
		t.Fatal(err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	err = grantctl.DaemonReload(ctlSock, testCtlToken, 2*time.Second)
	if err == nil {
		t.Fatal("expected an error when the daemon rejects the policy")
	}
	var refused *grantctl.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("expected *RefusedError (daemon answered), got %T: %v", err, err)
	}
	if !strings.Contains(refused.Reason, "rego parse error") {
		t.Errorf("compile error must be carried verbatim, got %q", refused.Reason)
	}
}

// TestDaemonReload_NilReloadIsRefused: a grant server built without a reload
// func must refuse the verb, not panic.
func TestDaemonReload_NilReloadIsRefused(t *testing.T) {
	ctlSock := filepath.Join(shortSockDir(t), "ctl.sock")

	gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.DaemonReload(ctlSock, testCtlToken, 2*time.Second); err == nil {
		t.Error("expected refusal when no reload func is wired")
	}
}

// TestReloadPolicy_SerializesCompiles is the DoS property from ADR 0066: a Rego
// recompile is the daemon's most expensive operation and every socket path is
// one goroutine per connection, so concurrent callers must never produce
// concurrent compiles.
func TestReloadPolicy_SerializesCompiles(t *testing.T) {
	var (
		mu       sync.Mutex
		inFlight int
		maxSeen  int
	)
	srv := &server{}
	fakeCompile := func() {
		mu.Lock()
		inFlight++
		if inFlight > maxSeen {
			maxSeen = inFlight
		}
		mu.Unlock()

		time.Sleep(5 * time.Millisecond) // stand in for the Rego compile

		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	// Exercise the same mutex reloadPolicy takes.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.reloadMu.Lock()
			fakeCompile()
			srv.reloadMu.Unlock()
		}()
	}
	wg.Wait()

	if maxSeen != 1 {
		t.Errorf("expected at most 1 concurrent compile, saw %d", maxSeen)
	}
}

// TestAgentSocket_RefusesReload is the core security regression for ADR 0066:
// the agent-facing socket must refuse reload. The sandboxed agent can reach this
// socket by design (shield_agentpaths.go grants a single-file write on
// daemon.sock so the hook can connect), and the peer-UID check cannot exclude it
// because the agent runs as the same UID. Serving a Rego recompile here is a
// fail-open DoS lever.
//
// The server is built with a nil evaluator on purpose: if the refusal ever
// regresses into actually serving reload, this test panics rather than passing.
func TestAgentSocket_RefusesReload(t *testing.T) {
	sock := filepath.Join(shortSockDir(t), "daemon.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srv := &server{idleTimeout: 2 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		srv.acceptConn(ctx, conn)
	}()

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Byte-for-byte what a prompt-injected agent would send.
	if _, err := conn.Write([]byte(`{"type":"control","op":"reload"}` + "\n")); err != nil {
		t.Fatal(err)
	}

	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.OK {
		t.Error("the agent socket must NOT serve reload")
	}
	if !strings.Contains(resp.Error, "agent socket") {
		t.Errorf("refusal should name the reason, got %q", resp.Error)
	}
}

// TestAgentSocket_StillServesPing: ping must stay on the agent socket — the
// single-instance guard probes it there to tell a live daemon from a squatter
// (singleton.go). Moving it would break that guard.
func TestAgentSocket_StillServesPing(t *testing.T) {
	sock := filepath.Join(shortSockDir(t), "daemon.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srv := &server{idleTimeout: 2 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		srv.acceptConn(ctx, conn)
	}()

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte(`{"type":"control","op":"ping"}` + "\n")); err != nil {
		t.Fatal(err)
	}

	var resp struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Error("ping must still be served on the agent socket")
	}
}
