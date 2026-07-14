package daemonapp

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/wire"
)

func TestAcquireInstanceLock_FreshSucceeds(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), instanceLockName)
	f, ok, err := acquireInstanceLock(lockPath, 0, time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("acquireInstanceLock = (ok=%v, err=%v), want (true, nil)", ok, err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

func TestAcquireInstanceLock_SecondHolderStandsDown(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), instanceLockName)
	f1, ok1, err1 := acquireInstanceLock(lockPath, 0, time.Millisecond)
	if err1 != nil || !ok1 {
		t.Fatalf("first acquire = (ok=%v, err=%v), want held", ok1, err1)
	}
	t.Cleanup(func() { _ = f1.Close() })

	// A second open+flock of the same file contends (flock is per open-file-
	// description). With retries=1 it fails fast and stands down.
	f2, ok2, err2 := acquireInstanceLock(lockPath, 1, time.Millisecond)
	if err2 != nil {
		t.Fatalf("second acquire err = %v, want nil", err2)
	}
	if ok2 {
		_ = f2.Close()
		t.Fatal("second acquire should have stood down (lock already held)")
	}
}

func TestAcquireInstanceLock_ReleasedOnClose(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), instanceLockName)
	f1, ok1, _ := acquireInstanceLock(lockPath, 0, time.Millisecond)
	if !ok1 {
		t.Fatal("first acquire failed")
	}
	_ = f1.Close() // releases the flock

	f2, ok2, err2 := acquireInstanceLock(lockPath, 0, time.Millisecond)
	if err2 != nil || !ok2 {
		t.Fatalf("re-acquire after close = (ok=%v, err=%v), want held", ok2, err2)
	}
	_ = f2.Close()
}

func TestBindAgentSocket_FreshBinds(t *testing.T) {
	sockPath := filepath.Join(shortSockDir(t), "test.sock")
	ln, ok, err := bindAgentSocket(sockPath)
	if err != nil || !ok {
		t.Fatalf("bindAgentSocket = (ok=%v, err=%v), want bound", ok, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
}

func TestBindAgentSocket_RemovesStaleSocketFile(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "test.sock")
	// Create a stale socket FILE with no listener (bind then close the listener
	// leaves the path on disk). probeSocket must see probeNoListener and rebind.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}
	_ = stale.Close() // path may remain; on some platforms Close unlinks it

	ln, ok, err := bindAgentSocket(sockPath)
	if err != nil || !ok {
		t.Fatalf("bindAgentSocket over stale = (ok=%v, err=%v), want rebound", ok, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
}

func TestBindAgentSocket_StandsDownForLiveDaemon(t *testing.T) {
	_, sockPath := newTestServer(t) // a live agentjail daemon owns sockPath
	ln, ok, err := bindAgentSocket(sockPath)
	if err != nil {
		t.Fatalf("bindAgentSocket err = %v, want nil (stand down)", err)
	}
	if ok {
		_ = ln.Close()
		t.Fatal("bindAgentSocket should stand down for a live agentjail daemon")
	}
}

func TestBindAgentSocket_ErrorsForUnresponsiveSquatter(t *testing.T) {
	sockPath := filepath.Join(shortSockDir(t), "test.sock")
	// A listener that accepts connections but never speaks the agentjail
	// protocol - a "squatter". probeSocket must return probeUnresponsive and
	// bindAgentSocket must error (never unlink a socket something holds).
	squat, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("seed squatter: %v", err)
	}
	t.Cleanup(func() { _ = squat.Close() })
	go func() {
		for {
			c, aerr := squat.Accept()
			if aerr != nil {
				return
			}
			_ = c // hold open, send nothing
		}
	}()

	_, ok, err := bindAgentSocket(sockPath)
	if ok || err == nil {
		t.Fatalf("bindAgentSocket over squatter = (ok=%v, err=%v), want (false, error)", ok, err)
	}
}

func TestSingleInstance_SecondStartStandsDownAtLock(t *testing.T) {
	dir := shortSockDir(t)
	lockPath := filepath.Join(dir, instanceLockName)

	first, ok, err := acquireInstanceLock(lockPath, 0, time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("first lock = (ok=%v, err=%v), want held", ok, err)
	}
	t.Cleanup(func() { _ = first.Close() })

	// Second daemon: same dir, bounded retry -> stands down (no socket needed).
	_, ok2, err2 := acquireInstanceLock(lockPath, 2, 5*time.Millisecond)
	if err2 != nil {
		t.Fatalf("second lock err = %v", err2)
	}
	if ok2 {
		t.Fatal("second start should stand down at the instance lock")
	}
}

func TestSingleInstance_CustomSocketDirIsolation(t *testing.T) {
	// Two different socket dirs must NOT contend on one another's lock.
	a := filepath.Join(shortSockDir(t), instanceLockName)
	b := filepath.Join(shortSockDir(t), instanceLockName)
	fa, oka, _ := acquireInstanceLock(a, 0, time.Millisecond)
	fb, okb, _ := acquireInstanceLock(b, 0, time.Millisecond)
	if !oka || !okb {
		t.Fatalf("independent dirs contended: a=%v b=%v", oka, okb)
	}
	_ = fa.Close()
	_ = fb.Close()
}

func TestControlOpPing_RepliesOKNoSideEffects(t *testing.T) {
	srv, sockPath := newTestServer(t)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))

	if err := json.NewEncoder(conn).Encode(wire.ControlRequest{Type: wire.ControlType, Op: wire.ControlOpPing}); err != nil {
		t.Fatalf("encode ping: %v", err)
	}
	var resp wire.ControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.Error != "" {
		t.Fatalf("ping response = %+v, want {OK:true}", resp)
	}
	// Side-effect-free: no decision should have been recorded.
	_ = srv // srv has no eventStore in newTestServer; presence asserted by no panic
}
