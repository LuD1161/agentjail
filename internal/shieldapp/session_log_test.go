package shieldapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenShieldSessionLog(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, time.July, 2, 19, 27, 44, 123, time.UTC)
	var stderr bytes.Buffer

	session, logger, err := openShieldSessionLog(stateDir, now, 42, false, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("gateway ready", "port", 9101)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	data, err := os.ReadFile(session.path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("log is not JSON: %v", err)
	}
	if record["msg"] != "gateway ready" || record["port"] != float64(9101) {
		t.Fatalf("record = %#v", record)
	}
	info, err := os.Stat(session.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	dirInfo, err := os.Stat(session.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
}

func TestOpenShieldSessionLogVerboseMirrorsStderr(t *testing.T) {
	var stderr bytes.Buffer
	session, logger, err := openShieldSessionLog(t.TempDir(), time.Now(), 42, true, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	logger.Warn("visible when verbose")
	if !bytes.Contains(stderr.Bytes(), []byte("visible when verbose")) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPruneOldShieldLogs(t *testing.T) {
	dir := t.TempDir()
	var preserve string
	for i := 0; i < 12; i++ {
		path := filepath.Join(dir, fmt.Sprintf("shield-20260702T1927%02d.000000000Z-%d.log", i, i))
		if err := os.WriteFile(path, []byte("log"), 0o600); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			preserve = path
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.log"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := pruneOldShieldLogs(dir, 10, preserve)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if _, err := os.Stat(preserve); err != nil {
		t.Fatalf("preserved current log: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "shield-*.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 10 {
		t.Fatalf("logs remaining = %d, want 10", len(matches))
	}
	if _, err := os.Stat(filepath.Join(dir, "daemon.log")); err != nil {
		t.Fatalf("unrelated log removed: %v", err)
	}
}

func TestOpenShieldSessionLogProducesInfoLogger(t *testing.T) {
	session, logger, err := openShieldSessionLog(t.TempDir(), time.Now(), 42, false, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if !logger.Enabled(context.Background(), slog.LevelInfo) || logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("logger level does not match Info default")
	}
}
