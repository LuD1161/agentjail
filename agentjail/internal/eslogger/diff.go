package eslogger

import (
	"container/list"
	"context"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Config controls the join. Defaults from observed production volume estimates:
// window of 200ms balances clock skew and false-positive rate.
type Config struct {
	// Window is the half-width of the time match window. An ES event at
	// time T matches an AW event with the same (ppid, exec_path) if the
	// AW event is in [T-Window, T+Window]. Default 200ms.
	Window time.Duration

	// Since drops events with Time < Since before the join runs.
	// Zero means no lower bound.
	Since time.Time
}

// Default returns the production default Config.
func Default() Config {
	return Config{Window: 200 * time.Millisecond}
}

// Diff streams two readers (es, aw) and emits one Delta per ES-only exec
// event into out. It returns parser stats for both streams.
//
// Memory: bounded by the number of in-flight events inside the window.
// At 100 ev/s sustained rate and a 200 ms window, expected
// steady-state state is ~20 unmatched events per side per bucket —
// safely under 1 MiB.
//
// Inspiration: SQLite's bounded-state hash join (sqlite/src/where.c,
// "loop ordering with bounded memory") — we partition by a discriminating
// key first so the per-bucket queues stay tiny.
func Diff(es, aw io.Reader, cfg Config, out func(Delta) error) (esStats, awStats Stats, err error) {
	if cfg.Window <= 0 {
		cfg.Window = 200 * time.Millisecond
	}
	j := newJoiner(cfg, out)

	// Streaming merge: pull one event at a time from each side,
	// choosing the earlier one to feed the joiner. We use channels +
	// goroutines for the merge so the joiner's logic stays linear.
	type item struct {
		ev   *NormEvent
		done bool
	}
	esCh := make(chan item, 64)
	awCh := make(chan item, 64)

	var esErr, awErr error
	go func() {
		defer close(esCh)
		esStats, esErr = StreamES(es, func(ev *NormEvent) error {
			if !cfg.Since.IsZero() && ev.Time.Before(cfg.Since) {
				return nil
			}
			esCh <- item{ev: ev}
			return nil
		})
		esCh <- item{done: true}
	}()
	go func() {
		defer close(awCh)
		awStats, awErr = StreamAW(aw, func(ev *NormEvent) error {
			if !cfg.Since.IsZero() && ev.Time.Before(cfg.Since) {
				return nil
			}
			awCh <- item{ev: ev}
			return nil
		})
		awCh <- item{done: true}
	}()

	// Pull next from each side, drop the done sentinel, and feed the
	// joiner in time order. Once one side is done, drain the other.
	var (
		nextES, nextAW *NormEvent
		esDone, awDone bool
	)
	pullES := func() {
		if esDone {
			nextES = nil
			return
		}
		x, ok := <-esCh
		if !ok || x.done {
			esDone = true
			nextES = nil
			return
		}
		nextES = x.ev
	}
	pullAW := func() {
		if awDone {
			nextAW = nil
			return
		}
		x, ok := <-awCh
		if !ok || x.done {
			awDone = true
			nextAW = nil
			return
		}
		nextAW = x.ev
	}
	pullES()
	pullAW()

	for nextES != nil || nextAW != nil {
		switch {
		case nextES == nil:
			if err = j.feed(nextAW); err != nil {
				return
			}
			pullAW()
		case nextAW == nil:
			if err = j.feed(nextES); err != nil {
				return
			}
			pullES()
		case !nextAW.Time.After(nextES.Time):
			if err = j.feed(nextAW); err != nil {
				return
			}
			pullAW()
		default:
			if err = j.feed(nextES); err != nil {
				return
			}
			pullES()
		}
	}
	if err = j.flush(); err != nil {
		return
	}

	// drain any straggler sentinels from a slow producer
	for range esCh {
	}
	for range awCh {
	}

	if esErr != nil {
		err = esErr
		return
	}
	if awErr != nil {
		err = awErr
		return
	}
	return
}

// joiner holds per-(ppid, exec_path) pending queues and emits deltas.
type joiner struct {
	cfg     Config
	out     func(Delta) error
	buckets map[bucketKey]*bucket
	clock   time.Time // monotonic-ish "current time" = last fed event's time
}

type bucketKey struct {
	ppid     int
	execPath string
}

type bucket struct {
	pendingES *list.List // *NormEvent
	pendingAW *list.List // *NormEvent
}

func newJoiner(cfg Config, out func(Delta) error) *joiner {
	return &joiner{
		cfg:     cfg,
		out:     out,
		buckets: make(map[bucketKey]*bucket),
	}
}

func (j *joiner) feed(ev *NormEvent) error {
	if ev.Time.After(j.clock) {
		j.clock = ev.Time
	}
	k := bucketKey{ppid: ev.PPID, execPath: ev.ExecPath}
	b, ok := j.buckets[k]
	if !ok {
		b = &bucket{pendingES: list.New(), pendingAW: list.New()}
		j.buckets[k] = b
	}

	// Try to match against the opposite-side queue. Walk front-to-back;
	// the queue is time-ordered so the first in-window candidate is the
	// closest. We accept any (ppid, exec_path) match — pid is
	// intentionally not part of the join key because the shim writes
	// its own pid (the wrapper) while ES writes the target pid.
	other := b.pendingAW
	if ev.Source == SourceAW {
		other = b.pendingES
	}
	for e := other.Front(); e != nil; e = e.Next() {
		cand := e.Value.(*NormEvent)
		if cand.Time.Before(ev.Time.Add(-j.cfg.Window)) {
			// too old to match this event (and the rest of this
			// queue is even fresher — but a previous tickGC should
			// already have evicted these; defensive only).
			continue
		}
		if absDuration(cand.Time.Sub(ev.Time)) <= j.cfg.Window {
			other.Remove(e)
			j.maybeGC(b, k)
			return j.tickGC()
		}
		// candidate is in the future beyond window; stop scanning.
		break
	}

	// No match: queue this event on its own side.
	if ev.Source == SourceES {
		b.pendingES.PushBack(ev)
	} else {
		b.pendingAW.PushBack(ev)
	}
	return j.tickGC()
}

// tickGC walks every bucket and evicts pending entries older than
// (clock - window). ES entries flushed this way become deltas; AW
// entries are dropped (we do not emit aw_only today). Buckets that
// become empty are deleted to bound memory.
func (j *joiner) tickGC() error {
	cutoff := j.clock.Add(-j.cfg.Window)
	for k, b := range j.buckets {
		// drain old ES → emit
		for e := b.pendingES.Front(); e != nil; {
			cand := e.Value.(*NormEvent)
			if cand.Time.Before(cutoff) {
				next := e.Next()
				b.pendingES.Remove(e)
				if err := j.emitESOnly(cand); err != nil {
					return err
				}
				e = next
				continue
			}
			break // queue is time-ordered; first non-old means rest is fresh
		}
		// drain old AW → discard
		for e := b.pendingAW.Front(); e != nil; {
			cand := e.Value.(*NormEvent)
			if cand.Time.Before(cutoff) {
				next := e.Next()
				b.pendingAW.Remove(e)
				e = next
				continue
			}
			break
		}
		if b.pendingES.Len() == 0 && b.pendingAW.Len() == 0 {
			delete(j.buckets, k)
		}
	}
	return nil
}

func (j *joiner) maybeGC(b *bucket, k bucketKey) {
	if b.pendingES.Len() == 0 && b.pendingAW.Len() == 0 {
		delete(j.buckets, k)
	}
}

// flush drains all remaining ES entries as deltas at end-of-stream.
// AW-only stragglers are silently discarded (not the signal we care about).
func (j *joiner) flush() error {
	for _, b := range j.buckets {
		for e := b.pendingES.Front(); e != nil; e = e.Next() {
			if err := j.emitESOnly(e.Value.(*NormEvent)); err != nil {
				return err
			}
		}
	}
	j.buckets = make(map[bucketKey]*bucket)
	return nil
}

func (j *joiner) emitESOnly(ev *NormEvent) error {
	return j.out(Delta{
		Kind:     "es_only",
		Time:     ev.Time,
		PID:      ev.PID,
		PPID:     ev.PPID,
		ExecPath: ev.ExecPath,
		Argv:     ev.Argv,
		Reason:   "endpoint security observed exec; agentjail capture did not",
	})
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// JobConfig controls the periodic reconcile loop that re-runs the ES↔AW
// diff against growing JSON-Lines files.
type JobConfig struct {
	ESPath string
	AWPath string

	// Interval is the ticker cadence. Zero defaults to one minute.
	Interval time.Duration

	// Window is the diff join window. Zero defaults to Default().Window.
	Window time.Duration

	// Retention is how long findings stay in memory for later inspection.
	// Zero defaults to ten minutes.
	Retention time.Duration

	// MaxFindings bounds in-memory retained findings. Zero defaults to 256.
	MaxFindings int
}

// Finding is a retained reconcile result.
type Finding struct {
	ObservedAt time.Time `json:"observed_at"`
	Delta      Delta     `json:"delta"`
}

// RunResult summarizes one reconcile pass.
type RunResult struct {
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Since       time.Time `json:"since"`
	ESStats     Stats     `json:"es_stats"`
	AWStats     Stats     `json:"aw_stats"`
	NewFindings int       `json:"new_findings"`
}

type openFunc func(string) (io.ReadCloser, error)

type ticker interface {
	C() <-chan time.Time
	Stop()
}

type realTicker struct {
	*time.Ticker
}

func (t realTicker) C() <-chan time.Time { return t.Ticker.C }

type jobState struct {
	lastRunStart time.Time
	findings     []Finding
	seen         map[string]time.Time
}

// Job runs the periodic reconcile loop. It owns the incremental cursor and
// the retained finding buffer; both are protected by a mutex so callers can
// snapshot state concurrently with the ticker loop.
type Job struct {
	cfg       JobConfig
	now       func() time.Time
	open      openFunc
	newTicker func(time.Duration) ticker

	mu    sync.Mutex
	state jobState
}

// NewJob builds a reconcile job with production defaults.
func NewJob(cfg JobConfig) *Job {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Window <= 0 {
		cfg.Window = Default().Window
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 10 * time.Minute
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 256
	}
	return &Job{
		cfg:  cfg,
		now:  time.Now,
		open: func(path string) (io.ReadCloser, error) { return os.Open(path) },
		newTicker: func(d time.Duration) ticker {
			return realTicker{Ticker: time.NewTicker(d)}
		},
		state: jobState{
			seen: make(map[string]time.Time),
		},
	}
}

// Run blocks until ctx is done, reconciling once per tick.
func (j *Job) Run(ctx context.Context) error {
	t := j.newTicker(j.cfg.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C():
			if _, err := j.RunOnce(ctx); err != nil {
				return err
			}
		}
	}
}

// RunOnce executes one reconcile pass against the configured files.
func (j *Job) RunOnce(ctx context.Context) (RunResult, error) {
	startedAt := j.now().UTC()

	j.mu.Lock()
	since := time.Time{}
	if !j.state.lastRunStart.IsZero() {
		since = j.state.lastRunStart.Add(-j.cfg.Window)
	}
	j.mu.Unlock()

	es, err := j.open(j.cfg.ESPath)
	if err != nil {
		return RunResult{}, err
	}
	defer es.Close()
	aw, err := j.open(j.cfg.AWPath)
	if err != nil {
		return RunResult{}, err
	}
	defer aw.Close()

	cfg := Config{Window: j.cfg.Window, Since: since}
	found := make([]Delta, 0, 8)
	esStats, awStats, err := Diff(es, aw, cfg, func(d Delta) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		found = append(found, d)
		return nil
	})
	if err != nil {
		return RunResult{}, err
	}

	completedAt := j.now().UTC()
	newFindings := j.recordFindings(completedAt, found)

	j.mu.Lock()
	j.state.lastRunStart = startedAt
	j.mu.Unlock()

	return RunResult{
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Since:       since,
		ESStats:     esStats,
		AWStats:     awStats,
		NewFindings: newFindings,
	}, nil
}

// Findings returns a copy of the retained findings buffer.
func (j *Job) Findings() []Finding {
	j.mu.Lock()
	defer j.mu.Unlock()

	out := make([]Finding, len(j.state.findings))
	copy(out, j.state.findings)
	return out
}

func (j *Job) recordFindings(observedAt time.Time, deltas []Delta) int {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.pruneLocked(observedAt)

	added := 0
	for _, d := range deltas {
		key := findingKey(d)
		if seenAt, ok := j.state.seen[key]; ok && observedAt.Sub(seenAt) <= j.cfg.Retention {
			continue
		}
		j.state.findings = append(j.state.findings, Finding{
			ObservedAt: observedAt,
			Delta:      d,
		})
		j.state.seen[key] = observedAt
		added++
	}

	j.pruneLocked(observedAt)
	return added
}

func (j *Job) pruneLocked(now time.Time) {
	if len(j.state.findings) > 0 {
		cutoff := now.Add(-j.cfg.Retention)
		keep := j.state.findings[:0]
		for _, f := range j.state.findings {
			if f.ObservedAt.Before(cutoff) {
				delete(j.state.seen, findingKey(f.Delta))
				continue
			}
			keep = append(keep, f)
		}
		j.state.findings = keep
	}

	if j.cfg.MaxFindings > 0 && len(j.state.findings) > j.cfg.MaxFindings {
		drop := len(j.state.findings) - j.cfg.MaxFindings
		for _, f := range j.state.findings[:drop] {
			delete(j.state.seen, findingKey(f.Delta))
		}
		trimmed := make([]Finding, len(j.state.findings)-drop)
		copy(trimmed, j.state.findings[drop:])
		j.state.findings = trimmed
	}
}

func findingKey(d Delta) string {
	key := d.Kind + "|" + d.Time.UTC().Format(time.RFC3339Nano) + "|" + d.ExecPath
	key += "|" + strconv.Itoa(d.PID) + "|" + strconv.Itoa(d.PPID)
	for _, arg := range d.Argv {
		key += "|" + arg
	}
	return key
}
