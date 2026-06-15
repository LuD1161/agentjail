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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

// updateCheckThrottle is the minimum time between successive update checks.
const updateCheckThrottle = 24 * time.Hour

// updateCheckURL is the primary endpoint for version checks (agentjail Worker).
// Overridable in tests.
var updateCheckURL = "https://releases.agentjail.io/v1/latest"

// updateCheckFallbackURL is the GitHub releases API used when the Worker is
// unreachable or returns an empty version.
var updateCheckFallbackURL = "https://api.github.com/repos/LuD1161/agentjail/releases/latest"

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

// githubRelease is kept for backward compatibility with existing tests.
type githubRelease = latestResponse

// latestResponse handles both the Worker shape {"version":"v1.2.3"} and the
// GitHub shape {"tag_name":"v1.2.3"}.
type latestResponse struct {
	Version string `json:"version"`
	TagName string `json:"tag_name"`
}

// fetchLatestVersion tries the Worker URL first, then falls back to GitHub.
// Returns "" when both sources fail or return no usable version.
func fetchLatestVersion(ctx context.Context) string {
	if v := fetchVersionFromURL(ctx, updateCheckURL); v != "" {
		return v
	}
	return fetchVersionFromURL(ctx, updateCheckFallbackURL)
}

// fetchVersionFromURL makes a GET request to url, adds analytics headers, and
// returns the version string found in the response. Returns "" on any error.
func fetchVersionFromURL(ctx context.Context, url string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "agentjail/"+version)
	req.Header.Set("X-Agentjail-Version", version)

	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var rel latestResponse
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return ""
	}
	if v := strings.TrimSpace(rel.Version); v != "" {
		return v
	}
	return strings.TrimSpace(rel.TagName)
}

// isSemver returns true when s looks like a numeric semver tag (starts with
// a digit after optional leading "v").
func isSemver(s string) bool {
	s = strings.TrimPrefix(s, "v")
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

// isNewerVersion returns true when latest is a semver tag that is strictly
// greater than current. Both must look like semver (vX.Y.Z or X.Y.Z); if
// either is non-numeric (e.g. "dev") the function returns false.
func isNewerVersion(current, latest string) bool {
	if current == "" || latest == "" {
		return false
	}
	// Both must be semver-shaped; non-numeric builds (dev, HEAD…) never compare.
	if !isSemver(current) || !isSemver(latest) {
		return false
	}
	// Strip leading "v" for numeric comparison.
	c := strings.TrimPrefix(current, "v")
	l := strings.TrimPrefix(latest, "v")
	if c == l {
		return false
	}
	// Compare semver tuples numerically (major.minor.patch).
	cv := parseSemver(c)
	lv := parseSemver(l)
	for i := 0; i < 3; i++ {
		if lv[i] > cv[i] {
			return true
		}
		if lv[i] < cv[i] {
			return false
		}
	}
	return false
}

// parseSemver splits "X.Y.Z[-suffix]" into [X, Y, Z] integers. Returns zeros
// for any components that are non-numeric or absent.
func parseSemver(s string) [3]int {
	// Trim any pre-release suffix after the first '-'.
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.SplitN(s, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

// maybeRunUpdateCheck fires the update check in a background goroutine if the
// throttle allows it. The goroutine has a hard 10 s deadline and all errors are
// silently discarded. Any update notice is printed to stderr; a heartbeat event
// is emitted via SendHeartbeat (respects opt-out).
func maybeRunUpdateCheck() {
	if !shouldRunUpdateCheck() {
		return
	}
	// Record the timestamp immediately (before the goroutine) so that parallel
	// invocations don't all fire at once.
	recordUpdateCheckTimestamp()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		latest := fetchLatestVersion(ctx)
		current := version
		newer := isNewerVersion(current, latest)

		if newer {
			_, brew := resolveExecutablePath()
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
