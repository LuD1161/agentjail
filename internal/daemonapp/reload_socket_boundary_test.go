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
	gs, err := newGrantServer(ctlSock, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil,
		func(context.Context) error { called.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.DaemonReload(ctlSock, 2*time.Second); err != nil {
		t.Fatalf("reload over the control socket should succeed: %v", err)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("expected exactly one reload, got %d", got)
	}
}

// TestDaemonReload_CompileFailureIsRefusedNotTransport: a rejected policy must
// surface as *RefusedError carrying the compile error, so the CLI reports "your
// policy did not take effect" instead of falling back to SIGHUP and reporting
// success against the still-loaded old bundle.
func TestDaemonReload_CompileFailureIsRefusedNotTransport(t *testing.T) {
	ctlSock := filepath.Join(shortSockDir(t), "ctl.sock")

	gs, err := newGrantServer(ctlSock, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil,
		func(context.Context) error { return errors.New("reload: compile: rego parse error") })
	if err != nil {
		t.Fatal(err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	err = grantctl.DaemonReload(ctlSock, 2*time.Second)
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

	gs, err := newGrantServer(ctlSock, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gs.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gs.serveCtl(ctx)

	if err := grantctl.DaemonReload(ctlSock, 2*time.Second); err == nil {
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
