package daemonapp

import "time"

// minReloadInterval bounds how often SIGHUP can drive a full Rego recompile.
// Chosen to be far below human reload cadence (an admin editing policy.yaml
// never notices it) and far above the rate needed to keep the daemon busy.
const minReloadInterval = 2 * time.Second

// reloadCoalescer bounds SIGHUP-triggered policy recompiles: at most one per
// interval, with a trigger arriving during the cooldown deferred rather than
// dropped. See ADR 0075.
//
// Why the signal path specifically, and not reloadPolicy itself: the control
// socket's daemon_reload is authenticated (ADR 0069) and answers with the
// compile verdict (ADR 0066). Coalescing there would make that verdict a lie —
// the reply would describe a recompile that has not happened yet. SIGHUP is the
// path that cannot be authenticated (Landlock does not mediate signals) and
// cannot report a verdict anyway, so it is the one that has to be bounded.
//
// Why deferred and not dropped: the CLI reloads via SIGHUP in several places
// (mcp.go, custom_rules.go). Silently skipping a reload would mean an admin's
// `agentjail mcp allow` reports success while their change never takes effect —
// the same silent-drift class of bug as ADR 0050/0073, reintroduced here.
type reloadCoalescer struct {
	interval time.Duration
	now      func() time.Time

	last    time.Time
	pending bool
}

func newReloadCoalescer(interval time.Duration, now func() time.Time) *reloadCoalescer {
	return &reloadCoalescer{interval: interval, now: now}
}

// request records a reload trigger. It reports either runNow (reload
// immediately) or a wait > 0 after which the caller must invoke a deferred
// reload. Both zero means the trigger collapsed into an already-scheduled
// reload and the caller does nothing.
func (c *reloadCoalescer) request() (runNow bool, wait time.Duration) {
	if c.pending {
		// A reload is already scheduled; it will pick up the current config
		// when it runs, so this trigger needs no separate recompile. This is
		// what bounds a storm: any number of SIGHUPs during the cooldown
		// collapse into exactly one recompile.
		return false, 0
	}
	if remaining := c.interval - c.now().Sub(c.last); remaining > 0 {
		c.pending = true
		return false, remaining
	}
	c.last = c.now()
	return true, 0
}

// deferredFired marks the scheduled reload as having run, restarting the
// cooldown. Call immediately before performing the deferred reload.
func (c *reloadCoalescer) deferredFired() {
	c.pending = false
	c.last = c.now()
}
