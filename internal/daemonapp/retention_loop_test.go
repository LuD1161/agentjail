package daemonapp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Guards AGE-225: a long-lived daemon must keep enforcing retention, not run it
// once at startup. See ADR 0101-periodic-retention.
func TestRetentionLoopFiresUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var fired atomic.Int64
	done := make(chan struct{})
	go func() {
		retentionLoop(ctx, 5*time.Millisecond, func() { fired.Add(1) })
		close(done)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retentionLoop did not return after ctx cancel")
	}
	if got := fired.Load(); got < 2 {
		t.Fatalf("retentionLoop fired %d times, want >= 2 (a startup-only run would fire 0)", got)
	}
}

// interval 0 means startup-only: the loop must return immediately without firing.
func TestRetentionLoopDisabledWhenIntervalZero(t *testing.T) {
	var fired atomic.Int64
	retentionLoop(context.Background(), 0, func() { fired.Add(1) })
	if got := fired.Load(); got != 0 {
		t.Fatalf("interval 0 fired %d times, want 0 (startup-only)", got)
	}
}
