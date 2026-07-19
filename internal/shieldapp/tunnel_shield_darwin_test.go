//go:build darwin

package shieldapp

// Failure-path coverage for startTunnelDarwin (AGE-149 T1.7). Standing up the
// real AgentjailTunnel.app + system extension needs root and an approved
// sysext, so these tests exercise the extracted pure-logic units instead:
// cleanup step ordering, the socket-register retry/timeout helper, the
// signal-drain arm/stop pair, and the fail-open fallback dispatch that fires
// before any process is spawned.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
)

// (a) Cleanup ordering: runCleanupSteps must call every non-nil step, in
// order, and skip nils without panicking - the shape startTunnelDarwin relies
// on for gwCancel -> gateway.Close -> dnsServer.Close -> caCleanup.
func TestRunCleanupStepsOrderAndNilSafety(t *testing.T) {
	var order []string
	runCleanupSteps(
		func() { order = append(order, "cancel") },
		nil, // caCleanup is nil whenever MITM never got wired up
		func() { order = append(order, "gateway") },
		func() { order = append(order, "dns") },
	)
	want := []string{"cancel", "gateway", "dns"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i, step := range want {
		if order[i] != step {
			t.Errorf("order[%d] = %q, want %q (full: %v)", i, order[i], step, order)
		}
	}
}

func TestRunCleanupStepsAllNilIsANoop(t *testing.T) {
	// Must not panic when every step is nil (e.g. cleanup fires before the
	// gateway was ever constructed).
	runCleanupSteps(nil, nil, nil)
}

// shortSocketDir returns a temp dir short enough for a unix socket path:
// t.TempDir() embeds the (long) test name, which overflows sockaddr_un's
// ~104-byte sun_path on macOS. See AGE-149 T1.7.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ajsock")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// (d) A stale/never-bound session socket must time out, not hang.
func TestWaitForSessionSocketTimesOutOnStaleSocket(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "stale.sock")
	start := time.Now()
	err := waitForSessionSocket(path, 200*time.Millisecond, 20*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("waitForSessionSocket returned nil for a socket that was never bound")
	}
	if elapsed > 2*time.Second {
		t.Errorf("waitForSessionSocket took %s, want it bounded near the 200ms timeout (not a hang)", elapsed)
	}
}

// (d) Retry behaviour: a socket that appears mid-poll must still succeed.
func TestWaitForSessionSocketSucceedsWhenListenerAppearsLate(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "late.sock")
	go func() {
		time.Sleep(60 * time.Millisecond)
		ln, err := net.Listen("unix", path)
		if err != nil {
			return
		}
		defer ln.Close()
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	if err := waitForSessionSocket(path, 2*time.Second, 20*time.Millisecond); err != nil {
		t.Fatalf("waitForSessionSocket did not succeed once the listener appeared: %v", err)
	}
}

// (b) Arming the signal drain must intercept SIGINT/SIGTERM so the process
// (and therefore the test) survives - Go's default action would otherwise
// terminate it, which is exactly the cleanup-skipping bug this guards
// against. Reaching the assertion after signalling ourselves IS the proof.
func TestArmSignalDrainSurvivesSIGINTAndSIGTERM(t *testing.T) {
	stop := armSignalDrain(syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("self-signal SIGINT: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("self-signal SIGTERM: %v", err)
	}
	// Give the drain goroutine a moment to consume both before the deferred
	// stop() races it; the process reaching here at all is the real
	// assertion.
	time.Sleep(50 * time.Millisecond)
}

// stop must be callable more than once's worth of safety is not required
// (startTunnelDarwin calls it exactly once), but it must not hang or panic
// when there is nothing left to drain.
func TestArmSignalDrainStopIsClean(t *testing.T) {
	stop := armSignalDrain(syscall.SIGINT)
	stop()
}

// (c) An extension bring-up failure (app binary missing) must fail OPEN into
// the caller's fallback - never panic, never os.Exit - because this failure
// happens before anything is spawned. This is real coverage of
// startTunnelDarwin itself, not just an extracted helper: AGENTJAIL_TUNNEL_APP
// points at a path that cannot exist, so the very first SYSEXT step fails.
func TestStartTunnelDarwinFailsOpenWhenAppMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist", "AgentjailTunnel")
	t.Setenv("AGENTJAIL_TUNNEL_APP", missing)

	var mu sync.Mutex
	fallbackCalled := false
	fallback := func() {
		mu.Lock()
		fallbackCalled = true
		mu.Unlock()
	}

	emitter := &captureEmitter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		startTunnelDarwin(context.Background(), nil, "/bin/echo", nil, "", true, emitter, fallback)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startTunnelDarwin did not return: a missing app binary must fail open, not hang")
	}

	mu.Lock()
	defer mu.Unlock()
	if !fallbackCalled {
		t.Fatal("fallback was not invoked for a missing AgentjailTunnel app - the tunnel-as-a-whole fail-open contract is broken")
	}

	if ev, ok := emitter.find(audit.TunnelExtensionStarted); !ok {
		t.Error("no tunnel.extension_started audit event for the failed bring-up attempt")
	} else if ev.Detail["failure_reason"] != "app_not_found" {
		t.Errorf("failure_reason = %q, want app_not_found", ev.Detail["failure_reason"])
	}
}
