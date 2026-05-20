package eslogger

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestParseESExec verifies the exec record projection works against the
// committed structure-reference fixture.
func TestParseESExec(t *testing.T) {
	line := []byte(`{"schema_version":1,"time":"2026-05-23T16:40:01.123456789Z","event":{"exec":{"target":{"audit_token":{"pid":50001},"ppid":50000,"executable":{"path":"/bin/ls"}},"args":["/bin/ls","-la"]}}}`)
	ev, ok, err := ParseESLine(line)
	if err != nil {
		t.Fatalf("ParseESLine err: %v", err)
	}
	if !ok || ev == nil {
		t.Fatalf("expected an event, got ok=%v ev=%v", ok, ev)
	}
	if ev.PID != 50001 || ev.PPID != 50000 {
		t.Errorf("pids: got pid=%d ppid=%d", ev.PID, ev.PPID)
	}
	if ev.ExecPath != "/bin/ls" {
		t.Errorf("exec path: got %q", ev.ExecPath)
	}
	if len(ev.Argv) != 2 || ev.Argv[0] != "/bin/ls" {
		t.Errorf("argv: got %v", ev.Argv)
	}
	if ev.Time.IsZero() {
		t.Error("time was zero")
	}
}

func TestParseESNonExecSkipped(t *testing.T) {
	// fork record from the spike fixture
	line := []byte(`{"schema_version":1,"time":"2026-05-23T16:40:01.456Z","event":{"fork":{"child":{"audit_token":{"pid":50002}}}}}`)
	_, ok, err := ParseESLine(line)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("fork event should be skipped, got ok=true")
	}
}

func TestParseESMalformed(t *testing.T) {
	_, _, err := ParseESLine([]byte(`{not json`))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestParseAWExec(t *testing.T) {
	line := []byte(`{"time_unix_nano":1779554401200000000,"body":"exec/shim","attributes":{"process.pid":50001,"process.parent_pid":50000,"argv":["/bin/ls","-la"],"real_program":"/bin/ls"}}`)
	ev, ok, err := ParseAWLine(line)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok || ev == nil {
		t.Fatalf("expected event")
	}
	if ev.PID != 50001 || ev.PPID != 50000 {
		t.Errorf("pids: got pid=%d ppid=%d", ev.PID, ev.PPID)
	}
	if ev.ExecPath != "/bin/ls" {
		t.Errorf("exec path: %q", ev.ExecPath)
	}
}

func TestParseAWNonExecSkipped(t *testing.T) {
	line := []byte(`{"time_unix_nano":1779554410000000000,"body":"policy.decision","attributes":{"rule_id":"x"}}`)
	_, ok, _ := ParseAWLine(line)
	if ok {
		t.Errorf("policy.decision should be skipped")
	}
}

// TestDiffFixture is the load-bearing test: feed the committed
// testdata/{es,aw}.jsonl into Diff and assert exactly one es_only delta
// for the absolute-path /bin/sh bypass, which the PATH shim cannot
// catch (absolute-path shell bypass) but ES does.
func TestDiffFixture(t *testing.T) {
	es := mustOpen(t, "testdata/es.jsonl")
	defer es.Close()
	aw := mustOpen(t, "testdata/aw.jsonl")
	defer aw.Close()

	var deltas []Delta
	esStats, awStats, err := Diff(es, aw, Default(), func(d Delta) error {
		deltas = append(deltas, d)
		return nil
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if esStats.Parsed != 3 {
		t.Errorf("es parsed: want 3, got %d", esStats.Parsed)
	}
	if awStats.Parsed != 2 {
		t.Errorf("aw parsed: want 2, got %d", awStats.Parsed)
	}
	if len(deltas) != 1 {
		t.Fatalf("want 1 delta, got %d: %+v", len(deltas), deltas)
	}
	if deltas[0].ExecPath != "/bin/sh" {
		t.Errorf("delta exec_path: want /bin/sh, got %q", deltas[0].ExecPath)
	}
	if deltas[0].Kind != "es_only" {
		t.Errorf("delta kind: %q", deltas[0].Kind)
	}
}

// TestDiffMatchWithinWindow: same exec, AW arrives slightly later but
// within the 200ms window — should be matched, no delta.
func TestDiffMatchWithinWindow(t *testing.T) {
	es := strings.NewReader(`{"schema_version":1,"time":"2026-05-23T16:40:00.000Z","event":{"exec":{"target":{"audit_token":{"pid":1},"ppid":99,"executable":{"path":"/usr/bin/git"}},"args":["git","status"]}}}` + "\n")
	aw := strings.NewReader(`{"time_unix_nano":1779554400100000000,"body":"exec/shim","attributes":{"process.pid":1,"process.parent_pid":99,"argv":["git","status"],"real_program":"/usr/bin/git"}}` + "\n")
	var deltas []Delta
	_, _, err := Diff(es, aw, Default(), func(d Delta) error {
		deltas = append(deltas, d)
		return nil
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(deltas) != 0 {
		t.Errorf("want 0 deltas (matched within window), got %d", len(deltas))
	}
}

// TestDiffOutsideWindow: same exec but AW arrives 500ms later — outside
// the 200ms window, should emit es_only.
func TestDiffOutsideWindow(t *testing.T) {
	es := strings.NewReader(`{"schema_version":1,"time":"2026-05-23T16:40:00.000Z","event":{"exec":{"target":{"audit_token":{"pid":1},"ppid":99,"executable":{"path":"/usr/bin/git"}},"args":["git","status"]}}}` + "\n")
	aw := strings.NewReader(`{"time_unix_nano":1779554400500000000,"body":"exec/shim","attributes":{"process.pid":1,"process.parent_pid":99,"argv":["git","status"],"real_program":"/usr/bin/git"}}` + "\n")
	var deltas []Delta
	_, _, err := Diff(es, aw, Default(), func(d Delta) error {
		deltas = append(deltas, d)
		return nil
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(deltas) != 1 {
		t.Errorf("want 1 delta (outside window), got %d", len(deltas))
	}
}

// TestDiffSinceFilter: --since cuts off both streams identically.
func TestDiffSinceFilter(t *testing.T) {
	es := mustOpen(t, "testdata/es.jsonl")
	defer es.Close()
	aw := mustOpen(t, "testdata/aw.jsonl")
	defer aw.Close()

	cfg := Default()
	// after the only ES-only exec → expect 0 deltas
	cfg.Since = time.Date(2026, 5, 23, 16, 40, 5, 0, time.UTC)

	var deltas []Delta
	_, _, err := Diff(es, aw, cfg, func(d Delta) error {
		deltas = append(deltas, d)
		return nil
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(deltas) != 0 {
		t.Errorf("want 0 deltas after since-filter, got %d", len(deltas))
	}
}

// TestDiffMalformedLineSkipped: a bad JSON line in either stream does
// not abort the join.
func TestDiffMalformedLineSkipped(t *testing.T) {
	es := strings.NewReader(`{not json
{"schema_version":1,"time":"2026-05-23T16:40:00.000Z","event":{"exec":{"target":{"audit_token":{"pid":1},"ppid":99,"executable":{"path":"/x"}},"args":["x"]}}}
`)
	aw := strings.NewReader("")
	var deltas []Delta
	esStats, _, err := Diff(es, aw, Default(), func(d Delta) error {
		deltas = append(deltas, d)
		return nil
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if esStats.Malformed != 1 {
		t.Errorf("want 1 malformed, got %d", esStats.Malformed)
	}
	if len(deltas) != 1 {
		t.Errorf("want 1 delta from the valid second line, got %d", len(deltas))
	}
}

// TestDiffEmptyInputs is the trivial-edge case.
func TestDiffEmptyInputs(t *testing.T) {
	var deltas []Delta
	_, _, err := Diff(bytes.NewReader(nil), bytes.NewReader(nil), Default(), func(d Delta) error {
		deltas = append(deltas, d)
		return nil
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(deltas) != 0 {
		t.Errorf("want 0 deltas, got %d", len(deltas))
	}
}

func TestJobRunOnceRetainsFindings(t *testing.T) {
	dir := t.TempDir()
	esPath := filepath.Join(dir, "es.jsonl")
	awPath := filepath.Join(dir, "aw.jsonl")
	writeFile(t, esPath, strings.Join([]string{
		`{"schema_version":1,"time":"2026-05-23T16:40:00.000Z","event":{"exec":{"target":{"audit_token":{"pid":1},"ppid":99,"executable":{"path":"/usr/bin/git"}},"args":["git","status"]}}}`,
		`{"schema_version":1,"time":"2026-05-23T16:40:00.050Z","event":{"exec":{"target":{"audit_token":{"pid":2},"ppid":99,"executable":{"path":"/bin/sh"}},"args":["/bin/sh","-c","id"]}}}`,
	}, "\n")+"\n")
	writeFile(t, awPath, `{"time_unix_nano":1779554400010000000,"body":"exec/shim","attributes":{"process.pid":1,"process.parent_pid":99,"argv":["git","status"],"real_program":"/usr/bin/git"}}`+"\n")

	job := NewJob(JobConfig{
		ESPath:      esPath,
		AWPath:      awPath,
		Window:      200 * time.Millisecond,
		Retention:   10 * time.Minute,
		MaxFindings: 8,
	})
	job.now = func() time.Time { return time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC) }

	res, err := job.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.NewFindings != 1 {
		t.Fatalf("want 1 new finding, got %d", res.NewFindings)
	}
	got := job.Findings()
	if len(got) != 1 {
		t.Fatalf("want 1 retained finding, got %d", len(got))
	}
	if got[0].Delta.ExecPath != "/bin/sh" {
		t.Fatalf("want /bin/sh delta, got %q", got[0].Delta.ExecPath)
	}
}

func TestJobRunTicksReconcile(t *testing.T) {
	dir := t.TempDir()
	esPath := filepath.Join(dir, "es.jsonl")
	awPath := filepath.Join(dir, "aw.jsonl")
	writeFile(t, esPath, `{"schema_version":1,"time":"2026-05-23T16:40:00.000Z","event":{"exec":{"target":{"audit_token":{"pid":2},"ppid":99,"executable":{"path":"/bin/sh"}},"args":["/bin/sh","-c","id"]}}}`+"\n")
	writeFile(t, awPath, "")

	job := NewJob(JobConfig{
		ESPath:      esPath,
		AWPath:      awPath,
		Interval:    time.Minute,
		Retention:   10 * time.Minute,
		MaxFindings: 8,
	})
	nowTimes := []time.Time{
		time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
	}
	var nowMu sync.Mutex
	job.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		if len(nowTimes) == 0 {
			return time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC)
		}
		x := nowTimes[0]
		nowTimes = nowTimes[1:]
		return x
	}
	ft := &fakeTicker{ch: make(chan time.Time, 1)}
	job.newTicker = func(time.Duration) ticker { return ft }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- job.Run(ctx)
	}()

	ft.ch <- time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC)
	waitFor(t, func() bool { return len(job.Findings()) == 1 })

	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("Run err: want context.Canceled, got %v", err)
	}
	if !ft.stopped {
		t.Fatalf("ticker was not stopped")
	}
}

func TestJobSuppressesOverlapDuplicates(t *testing.T) {
	dir := t.TempDir()
	esPath := filepath.Join(dir, "es.jsonl")
	awPath := filepath.Join(dir, "aw.jsonl")
	writeFile(t, esPath, `{"schema_version":1,"time":"2026-05-23T16:40:59.950Z","event":{"exec":{"target":{"audit_token":{"pid":2},"ppid":99,"executable":{"path":"/bin/sh"}},"args":["/bin/sh","-c","id"]}}}`+"\n")
	writeFile(t, awPath, "")

	job := NewJob(JobConfig{
		ESPath:      esPath,
		AWPath:      awPath,
		Window:      200 * time.Millisecond,
		Retention:   10 * time.Minute,
		MaxFindings: 8,
	})
	nowTimes := []time.Time{
		time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 41, 0, 100000000, time.UTC),
		time.Date(2026, 5, 23, 16, 41, 0, 100000000, time.UTC),
	}
	var nowMu sync.Mutex
	job.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		x := nowTimes[0]
		nowTimes = nowTimes[1:]
		return x
	}

	res1, err := job.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce #1: %v", err)
	}
	res2, err := job.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce #2: %v", err)
	}
	if res1.NewFindings != 1 {
		t.Fatalf("run1 findings: want 1, got %d", res1.NewFindings)
	}
	if res2.NewFindings != 0 {
		t.Fatalf("run2 findings: want 0 duplicate findings, got %d", res2.NewFindings)
	}
	if len(job.Findings()) != 1 {
		t.Fatalf("retained findings: want 1, got %d", len(job.Findings()))
	}
}

func TestJobPrunesByRetentionAndMax(t *testing.T) {
	dir := t.TempDir()
	esPath := filepath.Join(dir, "es.jsonl")
	awPath := filepath.Join(dir, "aw.jsonl")
	writeFile(t, awPath, "")

	job := NewJob(JobConfig{
		ESPath:      esPath,
		AWPath:      awPath,
		Window:      200 * time.Millisecond,
		Retention:   90 * time.Second,
		MaxFindings: 2,
	})
	nowTimes := []time.Time{
		time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 42, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 42, 0, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 43, 45, 0, time.UTC),
		time.Date(2026, 5, 23, 16, 43, 45, 0, time.UTC),
	}
	var nowMu sync.Mutex
	job.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		x := nowTimes[0]
		nowTimes = nowTimes[1:]
		return x
	}

	writeFile(t, esPath, `{"schema_version":1,"time":"2026-05-23T16:40:59.950Z","event":{"exec":{"target":{"audit_token":{"pid":2},"ppid":99,"executable":{"path":"/bin/sh"}},"args":["/bin/sh","-c","id"]}}}`+"\n")
	if _, err := job.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce #1: %v", err)
	}

	writeFile(t, esPath, strings.Join([]string{
		`{"schema_version":1,"time":"2026-05-23T16:40:59.950Z","event":{"exec":{"target":{"audit_token":{"pid":2},"ppid":99,"executable":{"path":"/bin/sh"}},"args":["/bin/sh","-c","id"]}}}`,
		`{"schema_version":1,"time":"2026-05-23T16:41:59.950Z","event":{"exec":{"target":{"audit_token":{"pid":3},"ppid":99,"executable":{"path":"/usr/bin/python3"}},"args":["python3","-c","print(1)"]}}}`,
	}, "\n")+"\n")
	if _, err := job.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce #2: %v", err)
	}
	if len(job.Findings()) != 2 {
		t.Fatalf("after run2 want max-sized buffer with 2 findings, got %d", len(job.Findings()))
	}

	writeFile(t, esPath, strings.Join([]string{
		`{"schema_version":1,"time":"2026-05-23T16:40:59.950Z","event":{"exec":{"target":{"audit_token":{"pid":2},"ppid":99,"executable":{"path":"/bin/sh"}},"args":["/bin/sh","-c","id"]}}}`,
		`{"schema_version":1,"time":"2026-05-23T16:41:59.950Z","event":{"exec":{"target":{"audit_token":{"pid":3},"ppid":99,"executable":{"path":"/usr/bin/python3"}},"args":["python3","-c","print(1)"]}}}`,
		`{"schema_version":1,"time":"2026-05-23T16:43:44.950Z","event":{"exec":{"target":{"audit_token":{"pid":4},"ppid":99,"executable":{"path":"/usr/bin/ruby"}},"args":["ruby","-e","puts 1"]}}}`,
	}, "\n")+"\n")
	if _, err := job.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce #3: %v", err)
	}

	got := job.Findings()
	if len(got) != 2 {
		t.Fatalf("want 2 retained findings after retention/max prune, got %d", len(got))
	}
	if got[0].Delta.ExecPath != "/usr/bin/python3" {
		t.Fatalf("want oldest fresh finding retained, got %q", got[0].Delta.ExecPath)
	}
	if got[1].Delta.ExecPath != "/usr/bin/ruby" {
		t.Fatalf("want newest finding retained, got %q", got[1].Delta.ExecPath)
	}
}

type fakeTicker struct {
	ch      chan time.Time
	stopped bool
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() { t.stopped = true }

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met before timeout")
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustOpen(t *testing.T, p string) *os.File {
	t.Helper()
	abs, _ := filepath.Abs(p)
	f, err := os.Open(abs)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	return f
}
