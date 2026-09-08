package daemonapp

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestCorePolicyRefreshFailureStopsStartup(t *testing.T) {
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
	dir := t.TempDir()
	socket := filepath.Join(dir, "daemon.sock")
	rules := filepath.Join(dir, "rules")
	called := false
	code := RunWithCorePolicySync([]string{
		"--socket", socket,
		"--log", filepath.Join(dir, "daemon.log"),
		"--policy", filepath.Join(dir, "policy.yaml"),
		"--rules", rules,
	}, func(got string) error {
		called = true
		if got != rules {
			t.Fatalf("refresh directory = %q, want %q", got, rules)
		}
		return errors.New("test refresh failure")
	})
	if code != 1 || !called {
		t.Fatalf("startup code=%d refreshed=%v", code, called)
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("daemon served before policy refresh succeeded: %v", err)
	}
}
