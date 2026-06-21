package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/notify"
	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/telemetry"
)

const (
	updateCheckInterval  = 6 * time.Hour
	updateCheckMaxJitter = 30 * time.Minute
	heartbeatThrottle    = 24 * time.Hour
)

// Fetcher abstracts the version-check call for testing.
type Fetcher interface {
	FetchLatestVersion(ctx context.Context, currentVersion string) (string, error)
}

// Notifier abstracts OS notification delivery for testing.
type Notifier interface {
	Send(ctx context.Context, title, message string) error
}

// UpdateChecker periodically checks for new agentjail versions and sends an
// OS notification when one is available.
type UpdateChecker struct {
	Version     string
	BasePath    string // ~/.agentjail
	Fetcher     Fetcher
	Notifier    Notifier
	ExeResolver func() (path string, isBrew bool)
	JitterFunc  func(max time.Duration) time.Duration
}

// Run starts the update-check loop with jittered initial delay, then 6h interval.
func (uc *UpdateChecker) Run(ctx context.Context) {
	jitter := uc.JitterFunc(updateCheckMaxJitter)
	slog.Info("update checker started", "initial_delay", jitter, "interval", updateCheckInterval)

	timer := time.NewTimer(jitter)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("update checker stopped")
			return
		case <-timer.C:
			if err := uc.checkOnce(ctx); err != nil {
				slog.Warn("update check failed", "err", err)
			}
			timer.Reset(updateCheckInterval)
		}
	}
}

func (uc *UpdateChecker) checkOnce(ctx context.Context) error {
	latest, err := uc.Fetcher.FetchLatestVersion(ctx, uc.Version)
	if err != nil {
		return fmt.Errorf("fetch latest version: %w", err)
	}

	if !selfupdate.IsNewerVersion(uc.Version, latest) {
		slog.Debug("no update available", "current", uc.Version, "latest", latest)
		return nil
	}

	if uc.alreadyNotified(latest) {
		slog.Debug("already notified for version", "version", latest)
		return nil
	}

	_, isBrew := uc.ExeResolver()
	var msg string
	if isBrew {
		msg = fmt.Sprintf("Update available: %s → %s. Run: brew upgrade agentjail", uc.Version, latest)
	} else {
		msg = fmt.Sprintf("Update available: %s → %s. Run: agentjail update", uc.Version, latest)
	}

	slog.Info("update available, sending notification", "current", uc.Version, "latest", latest, "brew", isBrew)

	notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := uc.Notifier.Send(notifyCtx, "agentjail", msg); err != nil {
		slog.Warn("OS notification failed", "err", err)
		return nil // don't write throttle file if notification failed
	}

	uc.recordNotified(latest)

	// Emit heartbeat telemetry (shared 24h throttle across CLI and daemon).
	if uc.shouldEmitHeartbeat() {
		if tp, terr := telemetry.DefaultPaths(); terr == nil {
			_ = telemetry.SendHeartbeat(ctx, tp, os.Getenv, uc.Version, latest, runtime.GOOS, "daemon", selfupdate.IsNewerVersion(uc.Version, latest))
		}
		uc.recordHeartbeat()
	}
	return nil
}

func (uc *UpdateChecker) throttlePath() string {
	return filepath.Join(uc.BasePath, "update-notified.version")
}

func (uc *UpdateChecker) alreadyNotified(version string) bool {
	b, err := os.ReadFile(uc.throttlePath())
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == version
}

func (uc *UpdateChecker) recordNotified(version string) {
	p := uc.throttlePath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(version), 0o600); err != nil {
		slog.Warn("write throttle file", "err", err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		slog.Warn("rename throttle file", "err", err)
		_ = os.Remove(tmp)
	}
}

func (uc *UpdateChecker) shouldEmitHeartbeat() bool {
	p := filepath.Join(uc.BasePath, "heartbeat.timestamp")
	b, err := os.ReadFile(p)
	if err != nil {
		return true
	}
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return true
	}
	return time.Since(ts) >= heartbeatThrottle
}

func (uc *UpdateChecker) recordHeartbeat() {
	p := filepath.Join(uc.BasePath, "heartbeat.timestamp")
	tmp := p + ".tmp"
	_ = os.WriteFile(tmp, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
	_ = os.Rename(tmp, p)
}

// osNotifier wraps notify.Send as a Notifier interface.
type osNotifier struct{}

func (osNotifier) Send(ctx context.Context, title, message string) error {
	return notify.Send(ctx, title, message)
}
