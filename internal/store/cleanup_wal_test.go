package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestCleanupCheckpointsWAL pins ADR 0071: Cleanup must fold the WAL back
// into the main DB, so history never lives only in -wal.
func TestCleanupCheckpointsWAL(t *testing.T) {
	s, path := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 200; i++ {
		if err := s.RecordDecision(ctx, DecisionRecord{
			Ts:        time.Now(),
			SessionID: "sess-wal",
			Agent:     "claude",
			ToolName:  "Bash",
			Action:    "allow",
		}); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}

	// Before the checkpoint the data sits in -wal, not the main DB.
	walBefore := fileSize(t, path+"-wal")
	if walBefore == 0 {
		t.Fatal("expected a non-empty WAL before cleanup")
	}

	// Nothing is purged (the common case) — the checkpoint must still run.
	if err := s.Cleanup(ctx, 30*24*time.Hour); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if walAfter := fileSize(t, path+"-wal"); walAfter >= walBefore {
		t.Errorf("WAL not truncated by cleanup checkpoint: before=%d after=%d", walBefore, walAfter)
	}
	if dbSize := fileSize(t, path); dbSize <= 4096 {
		t.Errorf("main DB still empty after checkpoint (%d bytes) — data is stranded in the WAL", dbSize)
	}

	// The checkpoint must not cost any data.
	got, err := s.ListDecisions(ctx, Filter{Limit: 500})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 200 {
		t.Errorf("got %d decisions after checkpoint, want 200", len(got))
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}
