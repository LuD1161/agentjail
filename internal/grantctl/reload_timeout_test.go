package grantctl

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func shortSock(t *testing.T, name string) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, name)
}

// serveOnce answers one request after delay, with the given ok/error.
func serveOnce(t *testing.T, sock string, delay time.Duration, ok bool, errMsg string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		var req Request
		if derr := json.NewDecoder(conn).Decode(&req); derr != nil {
			return
		}
		time.Sleep(delay) // stand in for a Rego compile
		_ = json.NewEncoder(conn).Encode(Response{OK: ok, Error: errMsg})
	}()
}

// TestDaemonReload_SlowRefusalIsNotMistakenForUnreachable is the regression for
// the bug this split exists for. Serving daemon_reload means compiling, which can
// outlast a dial budget sized in milliseconds. When both budgets were the same
// 200ms, a slow refusal timed out and surfaced as a transport error — so the CLI
// concluded "daemon absent", fell back to SIGHUP, and the operator never saw the
// verdict that their policy was rejected and never took effect.
func TestDaemonReload_SlowRefusalIsNotMistakenForUnreachable(t *testing.T) {
	sock := shortSock(t, "ctl.sock")
	// Reply takes far longer than the 200ms dial budget.
	serveOnce(t, sock, 400*time.Millisecond, false, "compile rego: unexpected token")

	err := DaemonReload(sock, "ctl-tok", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("slow refusal must surface as *RefusedError, not a transport error; got %T: %v", err, err)
	}
	if refused.Reason != "compile rego: unexpected token" {
		t.Errorf("compile error must survive verbatim, got %q", refused.Reason)
	}
}

// TestDaemonReload_SlowSuccessSurvivesDialBudget: the same split must not make a
// slow SUCCESS look like a failure either.
func TestDaemonReload_SlowSuccessSurvivesDialBudget(t *testing.T) {
	sock := shortSock(t, "ctl.sock")
	serveOnce(t, sock, 400*time.Millisecond, true, "")

	if err := DaemonReload(sock, "ctl-tok", 200*time.Millisecond); err != nil {
		t.Errorf("a slow but successful reload must not error: %v", err)
	}
}

// TestDaemonReload_AbsentDaemonStillFailsFast: splitting the budgets must not
// make an absent daemon wait out the long reply timeout — that path has to fail
// fast so the caller can fall back.
func TestDaemonReload_AbsentDaemonStillFailsFast(t *testing.T) {
	sock := shortSock(t, "nobody-home.sock") // never bound

	start := time.Now()
	err := DaemonReload(sock, "ctl-tok", 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error dialing an unbound socket")
	}
	var refused *RefusedError
	if errors.As(err, &refused) {
		t.Error("an absent daemon must NOT surface as a refusal — the caller would skip its fallback")
	}
	if elapsed > 2*time.Second {
		t.Errorf("absent daemon should fail fast on the dial budget, took %v", elapsed)
	}
}

func TestUpdateAudit_EncodesTypedOutcome(t *testing.T) {
	sock := shortSock(t, "ctl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received := make(chan Request, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var req Request
		if json.NewDecoder(conn).Decode(&req) != nil {
			return
		}
		received <- req
		_ = json.NewEncoder(conn).Encode(Response{OK: true})
	}()

	if err := UpdateAudit(sock, "ctl-tok", UpdateAuditCompleted, "v1.4.0", "linux", time.Second); err != nil {
		t.Fatalf("UpdateAudit: %v", err)
	}
	got := <-received
	if got.Type != ReqUpdateAudit || got.CtlToken != "ctl-tok" {
		t.Fatalf("request = %+v, want authenticated update audit", got)
	}
	if got.UpdateStatus != UpdateAuditCompleted || got.UpdateVersion != "v1.4.0" || got.UpdateOS != "linux" {
		t.Errorf("update audit fields = %+v", got)
	}
}
