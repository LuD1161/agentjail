package main

import (
	"context"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

func TestFailOpenMarkerSendsTelemetrySynchronously(t *testing.T) {
	origDefaultTelemetryPaths := defaultTelemetryPaths
	origSendFailOpen := sendFailOpen
	t.Cleanup(func() {
		defaultTelemetryPaths = origDefaultTelemetryPaths
		sendFailOpen = origSendFailOpen
	})

	base := t.TempDir()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	defaultTelemetryPaths = func() (telemetry.Paths, error) {
		return telemetry.Paths{Base: base}, nil
	}
	sendFailOpen = func(ctx context.Context, p telemetry.Paths, getenv func(string) string, version, goos, reason string) error {
		if reason != "dial-daemon" {
			t.Errorf("reason = %q, want %q", reason, "dial-daemon")
		}
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	go func() {
		failOpenMarker("codex", "dial-daemon")
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("failOpenMarker did not start telemetry send")
	}

	select {
	case <-done:
		t.Fatal("failOpenMarker returned before telemetry send completed")
	default:
	}

	close(release)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failOpenMarker did not return after telemetry send completed")
	}
}
