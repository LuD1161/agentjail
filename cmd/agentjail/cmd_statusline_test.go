package main

import "testing"

// TestDisplayVersion covers the git-describe -> status-line formatting: exact
// tags pass through, commits-past-tag collapse to "<tag>+N", and a dirty tree
// appends "*". The build-info fallback (empty/dev version) is exercised via the
// empty-string case, which yields whatever buildCommit() returns in the test
// binary; we only assert it does NOT surface the raw describe string.
func TestDisplayVersion(t *testing.T) {
	orig := version
	defer func() { version = orig }()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"exact tag", "v0.6.0", "v0.6.0"},
		{"exact tag dirty", "v0.6.0-dirty", "v0.6.0*"},
		{"commits past tag", "v0.6.0-5-g1a2b3c4", "v0.6.0+5"},
		{"commits past tag dirty", "v0.6.0-5-g1a2b3c4-dirty", "v0.6.0+5*"},
		{"prerelease tag exact", "v1.0.0-rc1", "v1.0.0-rc1"},
		{"prerelease tag commits past", "v1.0.0-rc1-3-gabc1234", "v1.0.0-rc1+3"},
		{"whitespace trimmed", "  v0.6.0  ", "v0.6.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version = tt.in
			if got := displayVersion(); got != tt.want {
				t.Errorf("displayVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDisplayVersionFallback verifies that build-time versions that carry no
// release information do NOT leak through as-is -- they route to the commit-hash
// fallback (which is empty in the test binary, built outside any -X ldflag).
func TestDisplayVersionFallback(t *testing.T) {
	orig := version
	defer func() { version = orig }()

	for _, in := range []string{"", "dev", "dev-1a2b3c4"} {
		version = in
		if got := displayVersion(); got == in && in != "" {
			t.Errorf("displayVersion(%q) = %q, want fallback (commit hash or empty)", in, got)
		}
	}
}
