// Package selfupdate_test covers the version-check and Homebrew-detection
// logic extracted into internal/selfupdate.
package selfupdate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuD1161/agentjail/internal/selfupdate"
)

// ---------------------------------------------------------------------------
// IsNewerVersion
// ---------------------------------------------------------------------------

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v2.0.0", true},
		{"v1.0.0", "v1.0.1", true},
		{"v1.1.0", "v1.0.0", false},  // older
		{"v1.0.0", "v1.0.0", false},  // same
		{"", "v1.0.0", false},        // empty current
		{"v1.0.0", "", false},        // empty latest
		{"dev", "v1.0.0", false},     // non-semver current → no false positive
		{"v1.0.0", "dev", false},     // non-semver latest
		{"v1.2.3", "v1.2.3", false},  // exactly equal
		{"v1.10.0", "v1.9.0", false}, // numeric comparison (10 > 9)
		{"v1.9.0", "v1.10.0", true},  // numeric comparison (10 > 9)
		// without "v" prefix
		{"1.0.0", "1.1.0", true},
		{"1.1.0", "1.0.0", false},
	}

	for _, tc := range cases {
		got := selfupdate.IsNewerVersion(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("IsNewerVersion(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// IsValid
// ---------------------------------------------------------------------------

func TestIsValid(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"v1.2.3", true},
		{"1.2.3", true},  // normalised to v1.2.3
		{"v0.0.1", true},
		{"dev", false},
		{"", false},
		{"HEAD", false},
		{"vfoo", false},
	}
	for _, tc := range cases {
		got := selfupdate.IsValid(tc.input)
		if got != tc.want {
			t.Errorf("IsValid(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Checker.FetchLatestVersion — helpers
// ---------------------------------------------------------------------------

type versionResponse struct {
	Version string `json:"version,omitempty"`
	TagName string `json:"tag_name,omitempty"`
}

func serveVersion(v versionResponse, code int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if code == 200 {
			b, _ := json.Marshal(v)
			_, _ = w.Write(b)
		}
	}))
}

// ---------------------------------------------------------------------------
// Checker.FetchLatestVersion — primary succeeds
// ---------------------------------------------------------------------------

func TestChecker_FetchLatestVersion_Primary(t *testing.T) {
	var gotUserAgent, gotVersionHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		gotVersionHeader = r.Header.Get("X-Agentjail-Version")
		b, _ := json.Marshal(versionResponse{Version: "v2.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := &selfupdate.Checker{
		PrimaryURL:  srv.URL,
		FallbackURL: "http://127.0.0.1:1", // unreachable — should not be called
	}

	ver, err := c.FetchLatestVersion(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "v2.0.0" {
		t.Errorf("got version %q, want v2.0.0", ver)
	}
	// Verify analytics headers were sent.
	if gotUserAgent != "agentjail/v1.0.0" {
		t.Errorf("User-Agent = %q, want agentjail/v1.0.0", gotUserAgent)
	}
	if gotVersionHeader != "v1.0.0" {
		t.Errorf("X-Agentjail-Version = %q, want v1.0.0", gotVersionHeader)
	}
}

// ---------------------------------------------------------------------------
// Checker.FetchLatestVersion — primary 500, fallback succeeds
// ---------------------------------------------------------------------------

func TestChecker_FetchLatestVersion_Fallback(t *testing.T) {
	primary := serveVersion(versionResponse{}, 500)
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(versionResponse{TagName: "v3.1.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer fallback.Close()

	c := &selfupdate.Checker{
		PrimaryURL:  primary.URL,
		FallbackURL: fallback.URL,
	}

	ver, err := c.FetchLatestVersion(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "v3.1.0" {
		t.Errorf("got version %q, want v3.1.0", ver)
	}
}

// ---------------------------------------------------------------------------
// Checker.FetchLatestVersion — both fail
// ---------------------------------------------------------------------------

func TestChecker_FetchLatestVersion_BothFail(t *testing.T) {
	primary := serveVersion(versionResponse{}, 500)
	defer primary.Close()
	fallback := serveVersion(versionResponse{}, 500)
	defer fallback.Close()

	c := &selfupdate.Checker{
		PrimaryURL:  primary.URL,
		FallbackURL: fallback.URL,
	}

	_, err := c.FetchLatestVersion(context.Background(), "v1.0.0")
	if err == nil {
		t.Fatal("expected error when both endpoints fail, got nil")
	}
}

// ---------------------------------------------------------------------------
// Checker.FetchVersionFromURL — bad JSON
// ---------------------------------------------------------------------------

func TestChecker_FetchVersionFromURL_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	c := &selfupdate.Checker{}
	_, err := c.FetchVersionFromURL(context.Background(), srv.URL, "v1.0.0")
	if err == nil {
		t.Fatal("expected error on bad JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// ResolveExecutablePath
// ---------------------------------------------------------------------------

func TestResolveExecutablePath_ReturnsNonEmpty(t *testing.T) {
	path, _ := selfupdate.ResolveExecutablePath()
	if path == "" {
		t.Error("ResolveExecutablePath returned empty path for test binary")
	}
}

func TestResolveExecutablePath_NotHomebrew(t *testing.T) {
	// The test binary lives in a temp directory managed by `go test`, not under
	// /homebrew/ or /cellar/, so Homebrew detection should be false.
	_, brew := selfupdate.ResolveExecutablePath()
	if brew {
		t.Error("test binary incorrectly identified as Homebrew-managed")
	}
}
