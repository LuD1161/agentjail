package telemetry

import (
	"context"
	"os"
	"time"
)

const (
	flushInterval      = 6 * time.Hour
	checkpointInterval = 60 * time.Second
	spoolMaxEvents     = 1000
	spoolMaxBytes      = 512 * 1024
)

// Recorder is the daemon-side telemetry orchestrator: it records decisions into
// in-memory stats, checkpoints them, and periodically flushes rollups + spool to
// the backend. It is the sole network egress for telemetry.
type Recorder struct {
	p            Paths
	getenv       func(string) string
	version      string
	goos, goarch string
	client       *Client
	consent      Consent
	stats        *Stats
	spool        *Spool
	enabled      bool
}

// New builds a Recorder, loads consent, and runs startup recovery (promote any
// orphan checkpoint into the spool). It also enqueues a session_start event.
func New(p Paths, getenv func(string) string, version, goos, goarch string, client *Client) (*Recorder, error) {
	c, err := LoadConsent(p)
	if err != nil {
		return nil, err
	}
	enabled, _ := Resolve(c, getenv)
	r := &Recorder{
		p: p, getenv: getenv, version: version, goos: goos, goarch: goarch,
		client: client, consent: c, stats: NewStats(),
		spool:   NewSpool(p, spoolMaxEvents, spoolMaxBytes),
		enabled: enabled,
	}
	if !enabled {
		return r, nil
	}
	r.recoverCheckpoint()
	_ = r.spool.Append(NewEnvEvent(c.AnonymousID, version, goos, goarch, r.getenv("AGENTJAIL_INSTALL_METHOD")))
	return r, nil
}

func (r *Recorder) Enabled() bool { return r.enabled }

// recoverCheckpoint promotes an orphan .partial checkpoint (left by a crash)
// into the spool as a completed decision_rollup, then deletes it.
func (r *Recorder) recoverCheckpoint() {
	b, err := os.ReadFile(r.p.Checkpoint())
	if err != nil {
		return // none (or unreadable) — nothing to recover
	}
	w, err := LoadCheckpoint(b)
	if err == nil && (len(w.ActionCounts) > 0 || len(w.RuleCounts) > 0) {
		_ = r.spool.Append(NewDecisionRollup(r.consent.AnonymousID, r.version, w.ActionCounts, w.RuleCounts, 0))
	}
	_ = os.Remove(r.p.Checkpoint())
}

// RecordDecision feeds one daemon decision into the in-memory stats.
func (r *Recorder) RecordDecision(action, ruleID string, elapsed time.Duration) {
	if !r.enabled {
		return
	}
	// Rule IDs are reported verbatim, including custom rules' user-chosen names
	// (custom/<name>/<rule>) — this is a deliberate product decision to learn what
	// custom rules people write. It is disclosed in docs/TELEMETRY.md.
	r.stats.RecordDecision(action, ruleID, elapsed)
}

// RecordPolicyConfig spools a policy_config snapshot (nil-safe via the daemon's
// guard; no-op when telemetry is disabled).
func (r *Recorder) RecordPolicyConfig(customRuleCount int, disabledRules []string) {
	if !r.enabled {
		return
	}
	_ = r.spool.Append(NewPolicyConfigEvent(r.consent.AnonymousID, r.version, customRuleCount, disabledRules))
}

// checkpoint writes the live decision counters to the .partial file.
func (r *Recorder) checkpoint() {
	if !r.enabled {
		return
	}
	b, err := r.stats.MarshalCheckpoint()
	if err != nil {
		return
	}
	tmp := r.p.Checkpoint() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, r.p.Checkpoint())
	}
}

// flush folds current stats into rollup events, appends them to the spool, then
// attempts to send the whole spool. On success it truncates the spool and removes
// the checkpoint; on failure the spool is retained for the next window.
func (r *Recorder) flush(ctx context.Context) error {
	if !r.enabled {
		return nil
	}
	w := r.stats.Snapshot()
	dropped, _ := r.spool.DrainDropped()
	if len(w.ActionCounts) > 0 || len(w.RuleCounts) > 0 || dropped > 0 {
		_ = r.spool.Append(NewDecisionRollup(r.consent.AnonymousID, r.version, w.ActionCounts, w.RuleCounts, dropped))
		p50, p95 := r.stats.LatencyPercentiles()
		_ = r.spool.Append(NewPerfRollup(r.consent.AnonymousID, r.version, p50, p95, 0))
	}
	r.stats.Reset()
	_ = os.Remove(r.p.Checkpoint())

	if !r.client.HasBackend() {
		return nil // keep spooled; nothing to send
	}
	evs, err := r.spool.ReadAll()
	if err != nil || len(evs) == 0 {
		return err
	}
	if err := r.client.Send(ctx, evs); err != nil {
		return err // keep spool, retry next window
	}
	return r.spool.Truncate()
}

// FlushForTest exposes flush() to other packages' tests. Not for production use.
func (r *Recorder) FlushForTest(ctx context.Context) error { return r.flush(ctx) }

// Run drives the checkpoint and flush tickers until ctx is cancelled, then
// performs one final flush (graceful shutdown).
func (r *Recorder) Run(ctx context.Context) {
	if !r.enabled {
		return
	}
	cpTick := time.NewTicker(checkpointInterval)
	flTick := time.NewTicker(flushInterval)
	defer cpTick.Stop()
	defer flTick.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = r.flush(fctx)
			cancel()
			return
		case <-cpTick.C:
			r.checkpoint()
		case <-flTick.C:
			_ = r.flush(ctx)
		}
	}
}
