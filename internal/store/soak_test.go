//go:build soak

// Soak harness: replicates a long-lived daemon, which calls Cleanup once at
// startup (daemonapp/main.go:910) and never again. Cleanup is the only WAL
// checkpoint (ADR 0071-retention-vacuum-and-wal-checkpoint), so this measures
// what a multi-week daemon does to the WAL. Never point this at a live DB.
//
// go test ./internal/store/ -tags soak -run TestSoak -v -timeout 30m
package store

import (
	"context"
	"fmt"

	"path/filepath"
	"sort"
	"testing"
	"time"
)

// fileSize is shared with cleanup_wal_test.go.

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	i := int(float64(len(d)-1) * p)
	return d[i]
}

// decisionN builds one realistic decision — a Bash tool call with argv, the
// shape that dominates a real session.
func decisionN(session string, n int) DecisionRecord {
	return DecisionRecord{
		Ts:        time.Now(),
		SessionID: session,
		Agent:     "claude-code",
		ToolName:  "Bash",
		Summary:   fmt.Sprintf("go test ./internal/pkg%d/...", n%50),
		Action:    "allow",
		RuleID:    "default-allow",
		Reason:    "no rule matched",
		Impact:    "low",
		ElapsedUs: 1200,
		CWD:       "/home/agent/repo",
		ToolInput: map[string]interface{}{
			"command":     fmt.Sprintf("go test ./internal/pkg%d/... --verbose", n%50),
			"description": "run the package tests",
		},
	}
}

// TestSoakLongSession writes N decisions through a store that, like a
// long-lived daemon, only ever checkpointed at startup.
func TestSoakLongSession(t *testing.T) {
	const (
		total  = 50000
		sample = 5000
	)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "soak.db")
	walPath := dbPath + "-wal"

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// Exactly what the daemon does at startup, once.
	if err := st.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatalf("startup cleanup: %v", err)
	}

	session := fmt.Sprintf("soak-%d", time.Now().UnixNano())
	lat := make([]time.Duration, 0, total)
	start := time.Now()

	t.Logf("%8s %12s %12s %10s %10s %10s", "writes", "db", "wal", "p50", "p99", "max")

	for i := 1; i <= total; i++ {
		w0 := time.Now()
		if err := st.RecordDecision(ctx, decisionN(session, i)); err != nil {
			t.Fatalf("write %d failed after %s: %v", i, time.Since(start), err)
		}
		lat = append(lat, time.Since(w0))

		if i%sample == 0 {
			s := make([]time.Duration, len(lat))
			copy(s, lat)
			sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
			t.Logf("%8d %12d %12d %10s %10s %10s",
				i, fileSize(t, dbPath), fileSize(t, walPath),
				pct(s, 0.50), pct(s, 0.99), s[len(s)-1])
		}
	}

	elapsed := time.Since(start)
	n, err := st.DecisionCount(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	t.Logf("--- wrote %d in %s (%.0f/sec), counted %d", total, elapsed,
		float64(total)/elapsed.Seconds(), n)
	t.Logf("--- final db=%d wal=%d", fileSize(t, dbPath), fileSize(t, walPath))

	if n != total {
		t.Errorf("silent loss: wrote %d, store counted %d", total, n)
	}
}
