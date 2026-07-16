package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSecretNeverReachesDisk greps the real SQLite bytes (+ WAL/SHM) after a
// real decision write. Unit tests assert what the redactor returns; this
// asserts what lands on disk, which is what ADR 0019-redaction-policy promises.
func TestSecretNeverReachesDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := "sk-proj-LIVETOKEN123456789abcdef"
	err = s.RecordDecision(context.Background(), DecisionRecord{
		Ts:        time.Now(),
		SessionID: "verify-session",
		ToolName:  "Bash",
		Action:    "allow",
		ToolInput: map[string]interface{}{
			"command": "curl -H 'Authorization: Bearer " + secret + "' https://api.example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("SECRET FOUND ON DISK in %s", filepath.Base(path+suffix))
		}
	}

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	rows, err := ro.ListDecisions(context.Background(), Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(rows))
	}
	got := rows[0].ToolInputRedacted
	want := `{"command":"curl -H 'Authorization: Bearer [redacted:auth-header]' https://api.example.com"}`
	if got != want {
		t.Errorf("replay rendering changed\n got: %s\nwant: %s", got, want)
	}
}
