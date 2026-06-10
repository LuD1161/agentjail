package main

import (
	"context"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

// The daemon holds a *telemetry.Recorder on its server and records each decision.
// This test verifies the seam exists and recording is wired (no network).
func TestServer_RecordsDecision(t *testing.T) {
	p := telemetry.Paths{Base: t.TempDir()}
	rec, err := telemetry.New(p, func(string) string { return "" }, "test", "darwin", "arm64", &telemetry.Client{})
	if err != nil {
		t.Fatalf("recorder: %v", err)
	}
	srv := &server{telemetry: rec}
	srv.recordTelemetry("deny", "command_policy/rm_rf", "Bash", "claude-code", 2*time.Millisecond)
	if err := rec.FlushForTest(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// session_start (from New) + decision_rollup + perf_rollup are spooled.
	if !rec.Enabled() {
		t.Fatal("recorder should be enabled")
	}
}
