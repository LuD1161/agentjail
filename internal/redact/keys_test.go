package redact

import "testing"

// Two packages decided this separately and each list had a hole the other
// covered. The cases below are that union: every one must hold for both the
// tool_input path and the network.db header path. AGE-232.
func TestShouldRedactKey(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
		why  string
	}{
		// The leak that prompted this: a real session wrote Dd-Api-Key
		// verbatim to network.db, because the header list matched exactly.
		{"Dd-Api-Key", true, "vendor-prefixed API key — the observed leak"},
		{"X-Goog-Api-Key", true, "vendor variant nobody enumerated"},
		{"anthropic-api-key", true, "vendor variant"},
		{"api-key", true, ""},
		{"x-api-key", true, ""},

		// The hole in the other direction: no substring matches "cookie", so
		// the substring list alone would have leaked it.
		{"Cookie", true, "session credential; matches no substring"},
		{"Set-Cookie", true, "same"},

		{"Authorization", true, ""},
		{"Proxy-Authorization", true, ""},
		{"X-Auth-Token", true, ""},
		{"Authentication", true, ""},
		{"X-Amz-Security-Token", true, "token substring"},
		{"password", true, ""},
		{"passphrase", true, ""},
		{"client_secret", true, ""},
		{"DATABASE_DSN", true, ""},
		{"signature", true, ""},

		// Must stay visible: these are what make a capture useful, and
		// over-redacting a baseline into uselessness is its own failure.
		{"Content-Type", false, ""},
		{"User-Agent", false, ""},
		{"Host", false, ""},
		{"Accept", false, ""},
		{"Content-Length", false, ""},
		{"X-Request-Id", false, ""},
	} {
		t.Run(tc.key, func(t *testing.T) {
			if got := ShouldRedactKey(tc.key); got != tc.want {
				verb := "must be redacted"
				if !tc.want {
					verb = "must NOT be redacted"
				}
				t.Errorf("ShouldRedactKey(%q) = %v, want %v — %s%s",
					tc.key, got, tc.want, verb, func() string {
						if tc.why != "" {
							return " (" + tc.why + ")"
						}
						return ""
					}())
			}
		})
	}
}

// Matching is case-insensitive: headers arrive in whatever case the client
// chose, and Go's textproto canonicalizes to yet another.
func TestShouldRedactKeyIsCaseInsensitive(t *testing.T) {
	for _, k := range []string{"AUTHORIZATION", "authorization", "AuThOrIzAtIoN", "DD-API-KEY", "dd-api-key"} {
		if !ShouldRedactKey(k) {
			t.Errorf("ShouldRedactKey(%q) = false, want true", k)
		}
	}
}
