package netpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A template we cannot understand must be an error. It used to decode into an
// empty MatchSpec -- which matches everything -- with an empty action, so it
// matched every request, enforced nothing, and logged `policy eval` as if it
// were working. AGE-227.
func TestLoadTemplatesRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "unknown top-level key (Nuclei-style shape)",
			yaml: `
id: wrong-shape
info:
  name: deny example.com
http:
  - host: [example.com]
    action: deny
`,
			wantErr: "field http not found",
		},
		{
			name: "unknown key inside match",
			yaml: `
id: bad-match
info:
  name: typo'd match field
match:
  hosts: [example.com]
action: deny
`,
			wantErr: "field hosts not found",
		},
		{
			name: "action value outside the allowed set",
			yaml: `
id: bad-action
info:
  name: typo'd action
match:
  host: [example.com]
action: DENY_ALL
`,
			wantErr: "expected one of allow, ask, deny",
		},
		{
			name: "no action at all",
			yaml: `
id: no-action
info:
  name: forgot the action
match:
  host: [example.com]
`,
			wantErr: "has no action",
		},
		{
			name: "invalid transport port",
			yaml: `
id: bad-port
info:
  name: invalid transport port
match:
  port: [70000]
action: deny
`,
			wantErr: "cannot unmarshal",
		},
		{
			name: "content but no id",
			yaml: `
info:
  name: forgot the id
match:
  host: [example.com]
action: deny
`,
			wantErr: "missing an id",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "t.yaml"), []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			err := ValidateDir(dir)
			if err == nil {
				t.Fatal("loaded without error — a template that enforces nothing must not load silently")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
			// The message has to name the file or the user cannot act on it.
			if !strings.Contains(err.Error(), "t.yaml") {
				t.Errorf("error = %q, want it to name the offending file", err)
			}
		})
	}
}

// The valid shapes must keep loading — including the ones the shipped packs
// use, and a scan-only template with no match constraints (a deliberate
// catch-all, e.g. DLP payload scanning, which must stay legal).
func TestLoadTemplatesAcceptsValid(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{
			name: "host deny",
			yaml: `
id: ok-deny
info:
  name: deny example.com
  author: agentjail
  severity: high
  description: >
    a multi-line description, as the shipped ssh.yaml uses
  tags: [test]
match:
  host: [example.com]
action: deny
reason: "denied"
`,
		},
		{
			name: "scan-only catch-all (no match constraints)",
			yaml: `
id: ok-scan-all
info:
  name: scan every payload for secrets
  severity: critical
scan:
  payload:
    - type: regex
      name: SSN
      patterns: ['\b\d{3}-\d{2}-\d{4}\b']
action: deny
`,
		},
		{
			name: "multi-doc with a trailing separator",
			yaml: `
id: ok-a
info:
  name: a
match:
  host: [a.example.com]
action: allow
---
id: ok-b
info:
  name: b
match:
  host: [b.example.com]
action: ask
---
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "t.yaml"), []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateDir(dir); err != nil {
				t.Fatalf("ValidateDir: %v", err)
			}
		})
	}
}

// The shipped packs must satisfy the rules we impose on everyone else. Strict
// decoding first caught ssh.yaml's info.description, which the schema lacked
// and had been silently dropping.
func TestShippedPacksLoadStrictly(t *testing.T) {
	dir := filepath.Join("..", "..", "agentpolicy", "packs")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("shipped packs dir not present: %v", err)
	}
	if err := ValidateDir(dir); err != nil {
		t.Fatalf("shipped packs do not load under strict validation: %v", err)
	}
}
