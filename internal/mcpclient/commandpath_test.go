package mcpclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveConfiguredCommandRejectsEmptyCommand(t *testing.T) {
	if _, err := resolveConfiguredCommand("  "); err == nil {
		t.Fatal("resolveConfiguredCommand accepted an empty command")
	}
}

func TestResolveConfiguredCommandAcceptsExplicitExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture-command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveConfiguredCommand(path)
	if err != nil {
		t.Fatalf("resolveConfiguredCommand: %v", err)
	}
	if got != path {
		t.Fatalf("resolved path = %q, want %q", got, path)
	}
}

func TestDiscoveryTimeoutAllowsStdioStartup(t *testing.T) {
	if got := discoveryTimeout(MCPServerConfig{Type: "stdio"}); got != 15*time.Second {
		t.Fatalf("stdio timeout = %s", got)
	}
	if got := discoveryTimeout(MCPServerConfig{Type: "http"}); got != 5*time.Second {
		t.Fatalf("http timeout = %s", got)
	}
}

func TestConfiguredCommandEnvIncludesResolvedInterpreterDirectory(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin:relative-bin")
	command := filepath.Join(t.TempDir(), "codex")
	pathValue := envValue(configuredCommandEnv(command), "PATH")
	directories := filepath.SplitList(pathValue)
	if len(directories) == 0 || directories[0] != filepath.Dir(command) {
		t.Fatalf("PATH = %q, want command directory first", pathValue)
	}
	if strings.Contains(pathValue, "relative-bin") {
		t.Fatalf("PATH retained a relative search directory: %q", pathValue)
	}
}
