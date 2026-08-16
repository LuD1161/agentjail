package store

import (
	"regexp"
	"strings"
)

// secretPattern matches one secret shape. group 0 replaces the whole match,
// n>0 replaces only that capture (keeps the key/scheme readable).
type secretPattern struct {
	name  string
	re    *regexp.Regexp
	group int
}

// secretPatterns run in order: PEM, auth shapes, provider tokens, key=value.
// Order is load-bearing and value classes exclude '[' and ']' so broad
// patterns can't re-match a narrow one's placeholder.
// See ADR 0084-redact-secret-values.
var secretPatterns = []secretPattern{
	{"pem-private-key", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), 0},

	// Must precede provider tokens, else the scheme word gets redacted instead.
	{"auth-header", regexp.MustCompile(`(?i)\bauthorization\b\s*[=:]\s*["']?(?:(?:bearer|basic|token|apikey)\s+)?([^\s"'&;\[\]]{6,})`), 1},
	{"bearer-token", regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})`), 1},

	{"aws-access-key-id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), 0},
	{"github-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`), 0},
	{"openai-key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b`), 0},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}\b`), 0},
	{"slack-token", regexp.MustCompile(`\bxox[bpcsa]-[A-Za-z0-9-]{10,}\b`), 0},
	{"google-api-key", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`), 0},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`), 0},

	{"url-credential", regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@\[\]]+):([^\s:/@\[\]]+)@`), 2},

	// Underscore is a word char, so \bsecret\b never fires on these.
	{"aws-secret", regexp.MustCompile(`(?i)\b(?:aws_secret_access_key|aws_session_token)\b\s*[=:]\s*["']?([A-Za-z0-9/+=_-]{16,})`), 1},

	// Broadest last. 'authorization' omitted — auth-header owns it.
	{"generic-credential", regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|passwd|password|passphrase)\b\s*[=:]\s*["']?([^\s"'&;\[\]]{6,})`), 1},
}

// secretHints gate the regex sweep; every pattern needs one. Kept as narrow as
// each pattern allows ("ghp_" not "gh"); the last six can't be narrower.
var secretHints = []string{
	"akia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"sk-", "npm_", "xox", "aiza", "eyj", "://", "aws_", "-----begin ",
	"auth", "bearer", "key", "secret", "token", "passw", "passphrase",
}

// minSecretLen is the shortest string any pattern can match ("Bearer " + 8).
const minSecretLen = 15

// redactSecretsInText replaces secret values with "[redacted:TYPE]", keeping
// surrounding text intact. Value-level half of ADR 0019-redaction-policy;
// runs alongside shouldRedactKey, not instead of it.
func redactSecretsInText(s string) string {
	if len(s) < minSecretLen || !mayContainSecret(s) {
		return s
	}
	for _, p := range secretPatterns {
		s = replaceGroup(s, p)
	}
	return s
}

// RedactText removes recognized credential values from unstructured text
// before it crosses a persistence or structured-log boundary.
// See ADR 0084-redact-secret-values.
func RedactText(s string) string {
	return redactSecretsInText(s)
}

// mayContainSecret is the cheap pre-filter keeping ordinary input off the
// regex path (~180ns vs ~18us).
func mayContainSecret(s string) bool {
	ls := strings.ToLower(s)
	for _, h := range secretHints {
		if strings.Contains(ls, h) {
			return true
		}
	}
	return false
}

// authSchemes may precede a credential; they are never the secret.
var authSchemes = map[string]bool{
	"bearer": true, "basic": true, "token": true,
	"apikey": true, "digest": true, "negotiate": true,
}

// isNotSecret rejects captures that can't be secrets. This is the idempotency
// guard: RE2 has no negative lookahead, so auth-header would otherwise redact
// its own scheme word on a second pass. See ADR 0084-redact-secret-values.
func isNotSecret(capture string) bool {
	return strings.HasPrefix(capture, "[redacted:") || authSchemes[strings.ToLower(capture)]
}

// replaceGroup applies one pattern, leaving the rest of the match verbatim.
func replaceGroup(s string, p secretPattern) string {
	locs := p.re.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	placeholder := "[redacted:" + p.name + "]"
	var b strings.Builder
	prev := 0
	for _, loc := range locs {
		start, end := loc[2*p.group], loc[2*p.group+1]
		// Skip: group absent, overlaps an earlier rewrite, or not a secret.
		if start < 0 || start < prev || isNotSecret(s[start:end]) {
			continue
		}
		b.WriteString(s[prev:start])
		b.WriteString(placeholder)
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}
