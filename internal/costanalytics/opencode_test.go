package costanalytics

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCodeReaderUsesReadOnlyConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode.db")
	setup, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`CREATE TABLE session (
		id TEXT, directory TEXT, model TEXT, cost REAL,
		tokens_input INTEGER, tokens_output INTEGER, tokens_reasoning INTEGER,
		tokens_cache_read INTEGER, tokens_cache_write INTEGER, time_created INTEGER
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`INSERT INTO session VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "/project", `{"id":"gpt-test"}`, 1.25, 10, 5, 0, 0, 0, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := NewOpenCodeReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if _, err := reader.ReadSessions(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.db.Exec("CREATE TABLE must_not_be_created (id INTEGER)"); err == nil {
		t.Fatal("read-only OpenCode reader allowed a write")
	}
}
