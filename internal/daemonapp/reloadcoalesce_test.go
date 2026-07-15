package daemonapp

import (
	"testing"
	"time"
)

// fakeClock drives the coalescer without sleeping, so these tests assert the
// bound itself rather than racing a wall clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestCoalescer() (*reloadCoalescer, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	return newReloadCoalescer(2*time.Second, clk.now), clk
}

// TestReloadCoalescer_FirstRequestRunsImmediately: the common case (an admin
// runs `agentjail mcp allow`, the CLI SIGHUPs once) must not be delayed.
func TestReloadCoalescer_FirstRequestRunsImmediately(t *testing.T) {
	c, _ := newTestCoalescer()
	runNow, wait := c.request()
	if !runNow {
		t.Errorf("first request should reload immediately, got runNow=false wait=%v", wait)
	}
}

// TestReloadCoalescer_StormCollapsesToOneReload is the ADR 0075 property: SIGHUP
// is reachable by a same-UID agent (Landlock does not mediate signals), so a
// tight SIGHUP loop must not translate into a tight recompile loop. Each
// recompile also invalidates the decision cache, so an unbounded storm degrades
// every subsequent eval toward the hook's ~30ms budget.
func TestReloadCoalescer_StormCollapsesToOneReload(t *testing.T) {
	c, clk := newTestCoalescer()

	// First trigger runs; the next 1000 arrive inside the cooldown.
	if runNow, _ := c.request(); !runNow {
		t.Fatal("first request should have run")
	}

	var immediate, scheduled int
	for i := 0; i < 1000; i++ {
		clk.advance(time.Millisecond) // a SIGHUP every 1ms
		runNow, wait := c.request()
		if runNow {
			immediate++
		}
		if wait > 0 {
			scheduled++
		}
	}

	if immediate != 0 {
		t.Errorf("%d of 1000 storm SIGHUPs forced an immediate recompile; want 0 (the rate bound is broken)", immediate)
	}
	// Exactly one deferred reload is scheduled; the other 999 collapse into it.
	if scheduled != 1 {
		t.Errorf("storm scheduled %d deferred reloads; want exactly 1", scheduled)
	}
}

// TestReloadCoalescer_DeferredRequestIsNotDropped: a trigger during the cooldown
// must still produce a reload. Dropping it would mean an admin's config change
// silently never takes effect — the silent-drift bug class of ADR 0050/0073.
func TestReloadCoalescer_DeferredRequestIsNotDropped(t *testing.T) {
	c, clk := newTestCoalescer()
	if runNow, _ := c.request(); !runNow {
		t.Fatal("first request should have run")
	}

	clk.advance(500 * time.Millisecond)
	runNow, wait := c.request()
	if runNow {
		t.Fatal("a request 500ms into a 2s cooldown should not run immediately")
	}
	if wait != 1500*time.Millisecond {
		t.Errorf("wait = %v; want the cooldown remainder (1.5s)", wait)
	}
}

// TestReloadCoalescer_ResumesAfterCooldown: the bound is a rate limit, not a
// one-shot latch — reloads must work normally once the interval has passed.
func TestReloadCoalescer_ResumesAfterCooldown(t *testing.T) {
	c, clk := newTestCoalescer()
	if runNow, _ := c.request(); !runNow {
		t.Fatal("first request should have run")
	}

	clk.advance(2 * time.Second)
	if runNow, _ := c.request(); !runNow {
		t.Error("a request after the full interval should reload immediately")
	}
}

// TestReloadCoalescer_DeferredFiredRestartsCooldown: after the deferred reload
// runs, the next trigger is bounded against THAT reload, not the original one.
// Otherwise a storm spanning the interval boundary would still recompile freely.
func TestReloadCoalescer_DeferredFiredRestartsCooldown(t *testing.T) {
	c, clk := newTestCoalescer()
	if runNow, _ := c.request(); !runNow {
		t.Fatal("first request should have run")
	}

	clk.advance(100 * time.Millisecond)
	if _, wait := c.request(); wait <= 0 {
		t.Fatal("expected a deferred reload to be scheduled")
	}

	// The deferred reload comes due and runs.
	clk.advance(1900 * time.Millisecond)
	c.deferredFired()

	// A trigger right after it must be bounded again, not run immediately.
	clk.advance(10 * time.Millisecond)
	if runNow, _ := c.request(); runNow {
		t.Error("a trigger 10ms after the deferred reload ran should be bounded; the cooldown did not restart")
	}
}
