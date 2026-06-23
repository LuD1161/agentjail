// Package selfupdate provides version-check and Homebrew-detection helpers
// shared between the CLI and the daemon.
//
// It exposes a [Checker] whose HTTP endpoints are injectable for testing, plus
// package-level helpers [IsNewerVersion], [IsValid], and [ResolveExecutablePath].
package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// DefaultCheckURL is the primary endpoint for version checks (Cloudflare Worker).
const DefaultCheckURL = "https://releases.agentjail.io/v1/latest"

// DefaultFallbackURL is the GitHub releases API used when the Worker is
// unreachable or returns a non-200 status.
const DefaultFallbackURL = "https://api.github.com/repos/LuD1161/agentjail/releases/latest"

// Checker fetches the latest agentjail release version from remote endpoints.
// The zero value is not usable; construct via literal or [New].
// All fields are exported so tests can inject fakes without reflection.
type Checker struct {
	// HTTPClient is used for all outbound requests.
	// When nil, a client with a 5 s timeout is used.
	HTTPClient *http.Client

	// PrimaryURL is tried first.  Defaults to [DefaultCheckURL].
	PrimaryURL string

	// FallbackURL is tried when PrimaryURL returns an error or non-200.
	// Defaults to [DefaultFallbackURL].
	FallbackURL string
}

// client returns the HTTPClient, falling back to a 5 s default.
func (c *Checker) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

// primaryURL returns PrimaryURL, falling back to DefaultCheckURL.
func (c *Checker) primaryURL() string {
	if c.PrimaryURL != "" {
		return c.PrimaryURL
	}
	return DefaultCheckURL
}

// fallbackURL returns FallbackURL, falling back to DefaultFallbackURL.
func (c *Checker) fallbackURL() string {
	if c.FallbackURL != "" {
		return c.FallbackURL
	}
	return DefaultFallbackURL
}

// latestResponse handles both the Worker shape {"version":"v1.2.3"} and the
// GitHub shape {"tag_name":"v1.2.3"}.
type latestResponse struct {
	Version   string `json:"version"`
	TagName   string `json:"tag_name"`
	Changelog string `json:"changelog"`
	Body      string `json:"body"`
}

// ReleaseInfo holds the version and changelog from a release endpoint.
type ReleaseInfo struct {
	Version   string
	Changelog string
}

// FetchLatestVersion tries the PrimaryURL first; on failure it tries
// FallbackURL.  It returns an error only when both endpoints fail.
// currentVersion is used in outbound analytics headers.
func (c *Checker) FetchLatestVersion(ctx context.Context, currentVersion string) (string, error) {
	v, err := c.FetchVersionFromURL(ctx, c.primaryURL(), currentVersion)
	if err == nil {
		return v, nil
	}
	// Primary failed — try fallback.
	v2, err2 := c.FetchVersionFromURL(ctx, c.fallbackURL(), currentVersion)
	if err2 != nil {
		return "", fmt.Errorf("selfupdate: both endpoints failed: primary: %w; fallback: %v", err, err2)
	}
	return v2, nil
}

// FetchVersionFromURL performs a single GET to url, adds analytics headers,
// decodes the JSON response as {"version":"..."} or {"tag_name":"..."}, and
// returns the version string.
//
// Returned errors are explicit: non-200 status, JSON decode failure, or empty
// version in the response body.
func (c *Checker) FetchVersionFromURL(ctx context.Context, url, currentVersion string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "agentjail/"+currentVersion)
	req.Header.Set("X-Agentjail-Version", currentVersion)

	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	var rel latestResponse
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode response from %s: %w", url, err)
	}

	if v := strings.TrimSpace(rel.Version); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(rel.TagName); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("GET %s: response contained no version field", url)
}

// FetchLatestRelease is like FetchLatestVersion but also returns the changelog.
// It tries the PrimaryURL first; on failure it tries FallbackURL.
// currentVersion is used in outbound analytics headers.
func (c *Checker) FetchLatestRelease(ctx context.Context, currentVersion string) (ReleaseInfo, error) {
	info, err := c.fetchReleaseFromURL(ctx, c.primaryURL(), currentVersion)
	if err == nil {
		return info, nil
	}
	info2, err2 := c.fetchReleaseFromURL(ctx, c.fallbackURL(), currentVersion)
	if err2 != nil {
		return ReleaseInfo{}, fmt.Errorf("selfupdate: both endpoints failed: primary: %w; fallback: %v", err, err2)
	}
	return info2, nil
}

// fetchReleaseFromURL performs a single GET to url, adds analytics headers,
// decodes the JSON response, and returns a ReleaseInfo with version and
// changelog fields populated.
func (c *Checker) fetchReleaseFromURL(ctx context.Context, url, currentVersion string) (ReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "agentjail/"+currentVersion)
	req.Header.Set("X-Agentjail-Version", currentVersion)

	resp, err := c.client().Do(req)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ReleaseInfo{}, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	var rel latestResponse
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return ReleaseInfo{}, fmt.Errorf("decode response from %s: %w", url, err)
	}

	var v string
	if vv := strings.TrimSpace(rel.Version); vv != "" {
		v = vv
	} else if vv := strings.TrimSpace(rel.TagName); vv != "" {
		v = vv
	}
	if v == "" {
		return ReleaseInfo{}, fmt.Errorf("GET %s: response contained no version field", url)
	}

	cl := strings.TrimSpace(rel.Changelog)
	if cl == "" {
		cl = strings.TrimSpace(rel.Body)
	}

	return ReleaseInfo{Version: v, Changelog: cl}, nil
}

// ---------------------------------------------------------------------------
// Package-level helpers
// ---------------------------------------------------------------------------

// normalize ensures s has a "v" prefix for use with golang.org/x/mod/semver.
func normalize(s string) string {
	if strings.HasPrefix(s, "v") {
		return s
	}
	return "v" + s
}

// IsValid reports whether s is a valid semver string (with or without the "v"
// prefix).
func IsValid(s string) bool {
	if s == "" {
		return false
	}
	return semver.IsValid(normalize(s))
}

// IsNewerVersion reports whether latest is a valid semver version strictly
// greater than current.  Both inputs may omit the leading "v".  Returns false
// if either value is empty, not a valid semver, or not strictly greater.
func IsNewerVersion(current, latest string) bool {
	if current == "" || latest == "" {
		return false
	}
	c := normalize(current)
	l := normalize(latest)
	if !semver.IsValid(c) || !semver.IsValid(l) {
		return false
	}
	return semver.Compare(l, c) > 0
}

// ResolveExecutablePath returns the resolved path of the running binary and
// whether it appears to be managed by Homebrew.  It evaluates symlinks so that
// a brew-installed binary (which lives under /opt/homebrew/Cellar/ and is
// symlinked into /opt/homebrew/bin/) is correctly detected.
func ResolveExecutablePath() (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	lower := strings.ToLower(resolved)
	brew := strings.Contains(lower, "/homebrew/") || strings.Contains(lower, "/cellar/")
	return resolved, brew
}
