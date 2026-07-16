package store

import (
	"strings"
	"testing"
)

// One positional-value case per secret type — the shape the key rule can't
// see (ADR 0084-redact-secret-values).
func TestRedactSecretsInText(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		leaked string // must not survive; empty means "check want only"
		unhurt string // substring that must survive redaction
	}{
		{
			// Exact want: scheme survives, exactly one placeholder. Guards the
			// pattern-order regression in ADR 0084-redact-secret-values.
			name:   "bearer token in a bash curl",
			in:     `curl -H 'Authorization: Bearer sk-proj-abc123def456ghi789' https://api.example.com`,
			want:   `curl -H 'Authorization: Bearer [redacted:auth-header]' https://api.example.com`,
			leaked: "sk-proj-abc123def456ghi789",
			unhurt: "https://api.example.com",
		},
		{
			name:   "aws access key id",
			in:     `aws configure set x AKIAIOSFODNN7EXAMPLE`,
			want:   `aws configure set x [redacted:aws-access-key-id]`,
			leaked: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:   "aws secret via export",
			in:     `export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
			leaked: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			unhurt: "AWS_SECRET_ACCESS_KEY",
		},
		{
			name:   "postgres url password",
			in:     `psql postgres://admin:hunter2pass@db.internal:5432/prod`,
			leaked: "hunter2pass",
			unhurt: "db.internal:5432/prod",
		},
		{
			name:   "github pat",
			in:     `git remote add o https://github_pat_11ABCDEFG0abcdefghijklmnop@github.com/x/y`,
			leaked: "github_pat_11ABCDEFG0abcdefghijklmnop",
		},
		{
			name:   "classic github token",
			in:     `GH_TOKEN is ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789`,
			leaked: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		},
		{
			name:   "openai key bare",
			in:     `OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345`,
			leaked: "sk-abcdefghijklmnopqrstuvwxyz012345",
		},
		{
			name:   "npm token",
			in:     `//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`,
			leaked: "npm_abcdefghijklmnopqrstuvwxyz0123456789",
		},
		{
			name:   "slack bot token",
			in:     `curl -d token=xoxb-1234567890-abcdefghijkl slack.com/api/x`,
			leaked: "xoxb-1234567890-abcdefghijkl",
		},
		{
			name:   "google api key",
			in:     `https://maps.googleapis.com/x?key=AIzaSyA1234567890abcdefghijklmnopqrstuv`,
			leaked: "AIzaSyA1234567890abcdefghijklmnopqrstuv",
		},
		{
			name:   "jwt",
			in:     `cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
			leaked: "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:   "pem private key block",
			in:     "cat <<EOF\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz123\nabc456\n-----END RSA PRIVATE KEY-----\nEOF",
			leaked: "MIIEowIBAAKCAQEAxyz123",
			unhurt: "cat <<EOF",
		},
		{
			name:   "generic password kv",
			in:     `mysql --user=root --password=s3cr3tp4ss --host=localhost`,
			leaked: "s3cr3tp4ss",
			unhurt: "--host=localhost",
		},
		{
			name: "clean command is untouched",
			in:   `go test ./internal/store/... -run TestRedact`,
			want: `go test ./internal/store/... -run TestRedact`,
		},
		{
			name: "ordinary prose with a keyish word is untouched",
			in:   `the keyword authorization appears here but carries no value`,
			want: `the keyword authorization appears here but carries no value`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSecretsInText(tt.in)
			if tt.want != "" && got != tt.want {
				t.Errorf("redactSecretsInText()\n got: %q\nwant: %q", got, tt.want)
			}
			if tt.leaked != "" && strings.Contains(got, tt.leaked) {
				t.Errorf("secret survived redaction: %q still in %q", tt.leaked, got)
			}
			if tt.unhurt != "" && !strings.Contains(got, tt.unhurt) {
				t.Errorf("context was destroyed: %q missing from %q", tt.unhurt, got)
			}
		})
	}
}

// Guards placeholder re-entry: a broad pattern must not match a narrow one's
// "[redacted:...]".
func TestRedactSecretsIsIdempotent(t *testing.T) {
	inputs := []string{
		`curl -H 'Authorization: Bearer sk-proj-abc123def456ghi789' https://x.com`,
		`export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
		`psql postgres://admin:hunter2pass@db.internal:5432/prod`,
		`token=xoxb-1234567890-abcdefghijkl`,
	}
	for _, in := range inputs {
		once := redactSecretsInText(in)
		twice := redactSecretsInText(once)
		if once != twice {
			t.Errorf("not idempotent\n in: %q\n 1x: %q\n 2x: %q", in, once, twice)
		}
	}
}

// The headline case: secret under "command", a key the key rule can't match.
func TestRedactToolInputRedactsPositionalValues(t *testing.T) {
	in := map[string]interface{}{
		"command": `curl -H 'Authorization: Bearer sk-proj-abc123def456ghi789' https://api.example.com`,
	}
	got := RedactToolInput(in)
	if strings.Contains(got, "sk-proj-abc123def456ghi789") {
		t.Errorf("bearer token persisted verbatim: %s", got)
	}
	if !strings.Contains(got, "api.example.com") {
		t.Errorf("command context destroyed, replay would be useless: %s", got)
	}
}

// The value pass must reach scalars nested in maps and slices.
func TestRedactToolInputNestedAndSliced(t *testing.T) {
	in := map[string]interface{}{
		"env": map[string]interface{}{
			"note": "AWS_SESSION_TOKEN=FwoGZXIvYXdzEBYaDNQ8example0123456789",
		},
		"args": []interface{}{
			"--header", "Authorization: Bearer abcdefghijklmnop",
		},
	}
	got := RedactToolInput(in)
	for _, leak := range []string{"FwoGZXIvYXdzEBYaDNQ8example0123456789", "abcdefghijklmnop"} {
		if strings.Contains(got, leak) {
			t.Errorf("secret survived at depth: %q in %s", leak, got)
		}
	}
}

// The value pass must not displace the key rule.
func TestRedactToolInputKeyRuleStillWins(t *testing.T) {
	in := map[string]interface{}{"api_key": "not-a-recognised-shape-just-a-blob"}
	got := RedactToolInput(in)
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("key rule regressed: %s", got)
	}
	if strings.Contains(got, "not-a-recognised-shape") {
		t.Errorf("key-matched value leaked: %s", got)
	}
}

func TestRedactDetailRedactsValues(t *testing.T) {
	got := redactDetail(map[string]string{
		"cmd": "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwx' https://x.com",
	})
	if strings.Contains(got, "sk-abcdefghijklmnopqrstuvwx") {
		t.Errorf("audit detail leaked a bearer token: %s", got)
	}
}

// Numbers recorded in ADR 0084-redact-secret-values. "Clean" is the common
// case and must stay off the regex path.
func BenchmarkRedactSecretsClean(b *testing.B) {
	s := `go build ./... && go vet ./internal/store/...`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = redactSecretsInText(s)
	}
}

func BenchmarkRedactSecretsHintNoMatch(b *testing.B) {
	// Hint hit, no match: worst case for wasted regex work.
	s := `rg --files-with-matches "keyword" ./docs --glob '!vendor' | head -20`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = redactSecretsInText(s)
	}
}

func BenchmarkRedactSecretsMatch(b *testing.B) {
	s := `curl -H 'Authorization: Bearer sk-proj-abc123def456ghi789' https://api.example.com`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = redactSecretsInText(s)
	}
}

func BenchmarkRedactToolInputTypical(b *testing.B) {
	in := map[string]interface{}{
		"command":     "git status --porcelain",
		"description": "Check working tree status",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = RedactToolInput(in)
	}
}
