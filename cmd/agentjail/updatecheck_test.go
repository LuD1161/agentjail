package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
		got := isNewerVersion(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

// TestParseSemver verifies the semver parser handles common edge cases.
func TestParseSemver(t *testing.T) {
	cases := []struct {
		input string
		want  [3]int
	}{
		{"1.2.3", [3]int{1, 2, 3}},
		{"1.2.3-beta", [3]int{1, 2, 3}}, // pre-release suffix stripped
		{"10.20.30", [3]int{10, 20, 30}},
		{"", [3]int{0, 0, 0}},
		{"1", [3]int{1, 0, 0}},
		{"1.2", [3]int{1, 2, 0}},
	}
	for _, tc := range cases {
		got := parseSemver(tc.input)
		if got != tc.want {
			t.Errorf("parseSemver(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// TestFetchLatestVersion_MockServer verifies that fetchLatestVersion parses the
// GitHub releases API response correctly.
func TestFetchLatestVersion_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(githubRelease{TagName: "v1.3.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	// Override the global URL for this test.
	orig := updateCheckURL
	updateCheckURL = srv.URL
	defer func() { updateCheckURL = orig }()

	got := fetchLatestVersion(t.Context())
	if got != "v1.3.0" {
		t.Fatalf("fetchLatestVersion = %q, want v1.3.0", got)
	}
}

// TestFetchLatestVersion_ServerError returns empty string on non-200.
func TestFetchLatestVersion_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	orig := updateCheckURL
	origFallback := updateCheckFallbackURL
	updateCheckURL = srv.URL
	updateCheckFallbackURL = srv.URL
	defer func() { updateCheckURL = orig; updateCheckFallbackURL = origFallback }()

	got := fetchLatestVersion(t.Context())
	if got != "" {
		t.Fatalf("expected empty on 500, got %q", got)
	}
}
