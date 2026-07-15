package secretsapp

import (
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/credentials"
)

// TestIdleClock_TouchResets verifies the activity clock advances and resets.
func TestIdleClock_TouchResets(t *testing.T) {
	var c idleClock
	c.touch()
	if got := c.idleFor(); got > 50*time.Millisecond {
		t.Fatalf("idleFor right after touch too large: %v", got)
	}
	time.Sleep(25 * time.Millisecond)
	if got := c.idleFor(); got < 15*time.Millisecond {
		t.Fatalf("idleFor did not advance: %v", got)
	}
	c.touch()
	if got := c.idleFor(); got > 15*time.Millisecond {
		t.Fatalf("touch did not reset idleFor: %v", got)
	}
}

// TestIdleWatchdog_FiresWhenIdleAndNoGrants: the watchdog fires once the broker
// is idle past the window with zero active grants (ADR 0058 self-exit path).
func TestIdleWatchdog_FiresWhenIdleAndNoGrants(t *testing.T) {
	var clock idleClock
	clock.last.Store(time.Now().Add(-time.Hour).UnixNano()) // already idle
	gm := credentials.NewGrantManager()
	fire := make(chan struct{})
	go idleWatchdog(20*time.Millisecond, &clock, gm, fire)

	select {
	case <-fire:
	case <-time.After(2 * time.Second):
		t.Fatal("idleWatchdog did not fire with zero active grants")
	}
}

// TestIdleWatchdog_HeldOffWhileGrantsActive is the ADR 0058 P1 guard: the broker
// must NOT self-exit while a grant is live (else the in-memory revokeFn is lost
// or a running session is torn down). It may only fire once grants clear.
func TestIdleWatchdog_HeldOffWhileGrantsActive(t *testing.T) {
	var clock idleClock
	clock.last.Store(time.Now().Add(-time.Hour).UnixNano()) // idle the whole time
	gm := credentials.NewGrantManager()
	id := gm.Register(&credentials.Grant{
		SecretName: "aws/prod",
		Backend:    "aws",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	fire := make(chan struct{})
	go idleWatchdog(20*time.Millisecond, &clock, gm, fire)

	// Must stay held off while the grant is active, despite being idle.
	select {
	case <-fire:
		t.Fatal("idleWatchdog fired while a grant was active (would corrupt ADR 0023 grant lifecycle)")
	case <-time.After(300 * time.Millisecond):
		// expected: held off
	}

	// After the grant is revoked, the watchdog may fire.
	if err := gm.Revoke(id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	select {
	case <-fire:
	case <-time.After(2 * time.Second):
		t.Fatal("idleWatchdog did not fire after grants cleared")
	}
}
