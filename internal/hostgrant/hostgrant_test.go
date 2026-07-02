package hostgrant

import "testing"

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		// --- accept cases ---
		{name: "simple hostname", raw: "api.example.com", want: "api.example.com"},
		{name: "uppercase is lowercased", raw: "API.Example.COM", want: "api.example.com"},
		{name: "leading/trailing whitespace trimmed", raw: "  api.example.com  ", want: "api.example.com"},
		{name: "trailing dot stripped", raw: "api.example.com.", want: "api.example.com"},
		{name: "leading wildcard with two labels", raw: "*.claude.ai", want: "*.claude.ai"},
		{name: "leading wildcard with three labels", raw: "*.sub.example.com", want: "*.sub.example.com"},
		{name: "wildcard lowercased", raw: "*.Claude.AI", want: "*.claude.ai"},
		{name: "subdomain host", raw: "api.internal.example.com", want: "api.internal.example.com"},

		// --- reject: empty / whitespace ---
		{name: "empty string", raw: "", wantErr: true},
		{name: "whitespace only", raw: "   ", wantErr: true},
		{name: "only a trailing dot", raw: ".", wantErr: true},

		// --- reject: scheme / URL ---
		{name: "http scheme", raw: "http://x", wantErr: true},
		{name: "https scheme", raw: "https://api.example.com", wantErr: true},
		{name: "bare scheme marker", raw: "ftp://example.com", wantErr: true},

		// --- reject: path / query / fragment ---
		{name: "path component", raw: "x/y", wantErr: true},
		{name: "path on real host", raw: "api.example.com/v1", wantErr: true},
		{name: "query component", raw: "api.example.com?x=1", wantErr: true},
		{name: "fragment component", raw: "api.example.com#frag", wantErr: true},

		// --- reject: embedded port ---
		{name: "embedded port", raw: "x:443", wantErr: true},
		{name: "embedded port on real host", raw: "api.example.com:443", wantErr: true},

		// --- reject: leading dot ---
		{name: "leading dot", raw: ".foo.com", wantErr: true},

		// --- reject: overly broad wildcard ---
		{name: "bare star", raw: "*", wantErr: true},
		{name: "star dot", raw: "*.", wantErr: true},
		{name: "wildcard public suffix com", raw: "*.com", wantErr: true},
		{name: "wildcard public suffix org", raw: "*.org", wantErr: true},
		{name: "wildcard public suffix net", raw: "*.net", wantErr: true},
		{name: "wildcard public suffix io", raw: "*.io", wantErr: true},
		{name: "wildcard with no suffix", raw: "*.", wantErr: true},
		{name: "wildcard mid-string not leading", raw: "foo.*.com", wantErr: true},

		// --- reject: malformed labels ---
		{name: "double dot", raw: "api..example.com", wantErr: true},
		{name: "no dot at all", raw: "localhost", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Validate(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate(%q) = %q, nil; want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("Validate(%q) = %q; want %q", tt.raw, got, tt.want)
			}
		})
	}
}
