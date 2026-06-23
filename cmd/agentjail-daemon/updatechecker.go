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

// osExitFn is the function used to exit the process. Overridden in tests.
var osExitFn = os.Exit

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

	// Auto-update fields
	AutoUpdate bool
	InstallDir string // ~/.agentjail/bin/
	PlistPath  string // path to launchd plist
	GOOS       string
	GOARCH     string
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

	newer := selfupdate.IsNewerVersion(uc.Version, latest)

	// Emit heartbeat telemetry on every successful check (shared 24h throttle).
	if uc.shouldEmitHeartbeat() {
		if tp, terr := telemetry.DefaultPaths(); terr == nil {
			_ = telemetry.SendHeartbeat(ctx, tp, os.Getenv, uc.Version, latest, runtime.GOOS, "daemon", newer)
		}
		uc.recordHeartbeat()
	}

	if !newer {
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
		return nil
	}

	uc.recordNotified(latest)

	// Auto-update: download, verify, swap, exit.
	if !uc.AutoUpdate {
		return nil
	}
	if selfupdate.SigningPubKey == "" {
		slog.Debug("auto-update: skipped (dev build, no signing key)")
		return nil
	}
	if uc.GOOS != "darwin" && uc.GOOS != "linux" {
		slog.Debug("auto-update: skipped (unsupported platform)")
		return nil
	}
	if isBrew {
		slog.Debug("auto-update: skipped (Homebrew installation)")
		return nil
	}

	uc.performAutoUpdate(ctx, latest)
	return nil
}

// performAutoUpdate downloads, verifies, and atomically swaps in the new
// binaries, then exits. The service manager (launchd on macOS, systemd on
// Linux) restarts the daemon at the new version. Called only on supported
// platforms, non-Homebrew, with AutoUpdate=true.
func (uc *UpdateChecker) performAutoUpdate(ctx context.Context, latest string) {
	slog.Info("auto-update: starting", "from", uc.Version, "to", latest)

	// 1. Download to temp dir.
	stagingDir, err := os.MkdirTemp("", "agentjail-update-*")
	if err != nil {
		slog.Error("auto-update: mktemp staging", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}
	defer os.RemoveAll(stagingDir)

	tarballName := selfupdate.TarballName(latest, uc.GOOS, uc.GOARCH)
	baseURL := selfupdate.UpdateURLBaseFn(latest)

	tarballPath := filepath.Join(stagingDir, tarballName)
	if err := selfupdate.DownloadFile(ctx, baseURL+"/"+tarballName, tarballPath, selfupdate.MaxDownloadBytes); err != nil {
		slog.Error("auto-update: download tarball", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}

	sumsPath := filepath.Join(stagingDir, "SHA256SUMS")
	if err := selfupdate.DownloadFile(ctx, baseURL+"/SHA256SUMS", sumsPath, 1024*1024); err != nil {
		slog.Error("auto-update: download SHA256SUMS", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}

	sigPath := filepath.Join(stagingDir, "SHA256SUMS.minisig")
	if err := selfupdate.DownloadFile(ctx, baseURL+"/SHA256SUMS.minisig", sigPath, 1024*1024); err != nil {
		slog.Error("auto-update: download minisig", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}

	// 2. Verify signature.
	if selfupdate.SigningPubKey != "" {
		if err := selfupdate.VerifyManifest(sumsPath, sigPath); err != nil {
			slog.Error("auto-update: signature verification failed", "err", err)
			uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
			return
		}
	}

	// 3. Verify tarball hash.
	if err := selfupdate.VerifyTarball(tarballPath, tarballName, sumsPath); err != nil {
		slog.Error("auto-update: hash verification failed", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}

	// 4. Extract.
	extractDir := filepath.Join(stagingDir, "extract")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		slog.Error("auto-update: mkdir extract", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}
	if err := selfupdate.ExtractTarball(tarballPath, extractDir); err != nil {
		slog.Error("auto-update: extract tarball", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}

	// 5. Backup existing binaries.
	backupDir, err := os.MkdirTemp("", "agentjail-backup-*")
	if err != nil {
		slog.Error("auto-update: mktemp backup", "err", err)
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", err)) //nolint:errcheck
		return
	}
	defer os.RemoveAll(backupDir)

	for _, bin := range selfupdate.UpdateBinaries {
		src := filepath.Join(uc.InstallDir, bin)
		dst := filepath.Join(backupDir, bin)
		if err := selfupdate.CopyFile(src, dst); err != nil {
			if !os.IsNotExist(err) {
				slog.Warn("auto-update: backup failed", "bin", bin, "err", err)
			}
		}
	}

	// 6. Swap binaries.
	var swapErr error
	swappedCount := 0
	for _, bin := range selfupdate.UpdateBinaries {
		src := filepath.Join(extractDir, bin)
		dst := filepath.Join(uc.InstallDir, bin)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			continue // binary not in this release
		}
		if err := selfupdate.AtomicReplaceBinary(src, dst); err != nil {
			swapErr = fmt.Errorf("swap %s: %w", bin, err)
			break
		}
		swappedCount++
	}

	if swapErr != nil {
		slog.Error("auto-update: swap failed, rolling back", "err", swapErr)
		for _, bin := range selfupdate.UpdateBinaries[:swappedCount] {
			backup := filepath.Join(backupDir, bin)
			dst := filepath.Join(uc.InstallDir, bin)
			if _, statErr := os.Stat(backup); statErr == nil {
				_ = selfupdate.AtomicReplaceBinary(backup, dst)
			}
		}
		selfupdate.RestartDaemon(uc.PlistPath) //nolint:errcheck
		uc.Notifier.Send(ctx, "agentjail", fmt.Sprintf("Auto-update failed: %v", swapErr)) //nolint:errcheck
		return
	}

	slog.Info("auto-update: binaries swapped, exiting for restart", "version", latest, "swapped", swappedCount)

	// 7. Exit — launchd KeepAlive restarts the new daemon.
	osExitFn(0)
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
