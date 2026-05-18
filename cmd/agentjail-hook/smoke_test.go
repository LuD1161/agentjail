//go:build smoke

// Package main — build-tag-gated end-to-end smoke test.
//
// This file is excluded from normal `go test ./...` runs (the `smoke` build
// tag is not set by default). To run it:
//
//	go test -v -tags smoke ./cmd/agentjail-hook/
//
// It shells out to cmd/agentjail-hook/test/smoke.sh from the repo root and
// asserts exit 0. The shell script builds the binaries, starts the daemon,
// runs all fixtures, and reports per-fixture pass/fail with latency.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestE2ESmoke runs the full end-to-end smoke harness (smoke.sh) and
// asserts it exits 0 (all fixtures pass).
func TestE2ESmoke(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("smoke.sh requires a POSIX shell; skipping on Windows")
	}

	// Locate smoke.sh relative to this file.
	// __file__ is not available in Go; we use the repo root approach:
	// the test is always run via `go test ./cmd/agentjail-hook/` so the
	// working directory may vary. We locate the script relative to the
	// directory of this source file using runtime.Caller.
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate smoke.sh")
	}
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	smokeScript := filepath.Join(repoRoot, "cmd", "agentjail-hook", "test", "smoke.sh")

	if _, err := os.Stat(smokeScript); err != nil {
		t.Fatalf("smoke.sh not found at %s: %v", smokeScript, err)
	}

	cmd := exec.Command("bash", smokeScript)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("smoke.sh exited non-zero: %v", err)
	}
}
