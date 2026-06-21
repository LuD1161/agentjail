// updatecheck.go — lightweight, throttled update checker + heartbeat emitter.
//
// Called on every CLI invocation (except "telemetry") but gated to fire at most
// once per ~24 h via a timestamp file under ~/.agentjail. The check is fully
// async and non-blocking: it runs in a goroutine with a short timeout and all
// network / file errors are silently ignored.
//
// When a newer version is available it prints a single concise notice to stderr.
// It also emits a heartbeat telemetry event (immediate send, respects opt-out).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/telemetry"
)

// updateCheckThrottle is the minimum time between successive update checks.
const updateCheckThrottle = 24 * time.Hour

// defaultChecker is the package-level Checker used by maybeRunUpdateCheck and
// performUpdate. Tests override PrimaryURL / FallbackURL to point at mock
// servers without touching the production constants.
var defaultChecker = selfupdate.Checker{}

// updateCheckTimestampFile returns the path to the throttle timestamp file.
func updateCheckTimestampFile() (string, error) {
	p, err := telemetry.DefaultPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(p.Base, "update-check.timestamp"), nil
}

// shouldRunUpdateCheck returns true when more than updateCheckThrottle has
// elapsed since the last check (or the timestamp file is absent/unreadable).
func shouldRunUpdateCheck() bool {
	f, err := updateCheckTimestampFile()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(f)
	if err != nil {
		// File absent → first-ever check.
		return true
	}
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return true // corrupt → recheck
	}
	return time.Since(ts) >= updateCheckThrottle
}

// recordUpdateCheckTimestamp writes the current time to the throttle file.
// Errors are silently ignored (best-effort).
func recordUpdateCheckTimestamp() {
	f, err := updateCheckTimestampFile()
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(f), 0o700)
	_ = os.WriteFile(f, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

// maybeRunUpdateCheck fires the update check in a background goroutine if the
// throttle allows it. The goroutine has a hard 10 s deadline and all errors are
// silently discarded. Any update notice is printed to stderr; a heartbeat event
// is emitted via SendHeartbeat (respects opt-out).
func maybeRunUpdateCheck() {
	if os.Getenv("AGENTJAIL_NO_UPDATE_CHECK") != "" {
		return
	}
	if !shouldRunUpdateCheck() {
		return
	}
	// Record the timestamp immediately (before the goroutine) so that parallel
	// invocations don't all fire at once.
	recordUpdateCheckTimestamp()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		latest, _ := defaultChecker.FetchLatestVersion(ctx, version)
		current := version
		newer := selfupdate.IsNewerVersion(current, latest)

		if newer {
			_, brew := selfupdate.ResolveExecutablePath()
			if brew {
				fmt.Fprintf(os.Stderr,
					"agentjail: update available: %s → %s  (run: brew upgrade agentjail)\n",
					current, latest,
				)
			} else {
				fmt.Fprintf(os.Stderr,
					"agentjail: update available: %s → %s  (run: agentjail update)\n",
					current, latest,
				)
			}
		}

		// Emit heartbeat telemetry (best-effort; ignores ErrNoBackend and opt-out).
		if tp, err := telemetry.DefaultPaths(); err == nil {
			_ = telemetry.SendHeartbeat(ctx, tp, os.Getenv, current, latest, runtime.GOOS, newer)
		}
	}()
}
