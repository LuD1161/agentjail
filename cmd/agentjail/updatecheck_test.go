package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuD1161/agentjail/internal/selfupdate"
)

// TestIsNewerVersion verifies the semver comparison helper.
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
		{"v1.10.0", "v1.9.0", false}, // major segment matters (10 > 9)
		{"v1.9.0", "v1.10.0", true},  // major segment matters (10 > 9)
	}

	for _, tc := range cases {
		got := selfupdate.IsNewerVersion(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("IsNewerVersion(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

// TestFetchLatestVersion_MockServer verifies that FetchLatestVersion parses the
// GitHub releases API response correctly.
func TestFetchLatestVersion_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(struct {
			TagName string `json:"tag_name"`
		}{TagName: "v1.3.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	// Override the checker's primary URL for this test.
	orig := defaultChecker.PrimaryURL
	defaultChecker.PrimaryURL = srv.URL
	defer func() { defaultChecker.PrimaryURL = orig }()

	got, err := defaultChecker.FetchLatestVersion(t.Context(), version)
	if err != nil {
		t.Fatalf("FetchLatestVersion error: %v", err)
	}
	if got != "v1.3.0" {
		t.Fatalf("FetchLatestVersion = %q, want v1.3.0", got)
	}
}

// TestFetchLatestVersion_ServerError returns empty string on non-200.
func TestFetchLatestVersion_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	orig := defaultChecker.PrimaryURL
	origFallback := defaultChecker.FallbackURL
	defaultChecker.PrimaryURL = srv.URL
	defaultChecker.FallbackURL = srv.URL
	defer func() {
		defaultChecker.PrimaryURL = orig
		defaultChecker.FallbackURL = origFallback
	}()

	got, _ := defaultChecker.FetchLatestVersion(t.Context(), version)
	if got != "" {
		t.Fatalf("expected empty on 500, got %q", got)
	}
}
