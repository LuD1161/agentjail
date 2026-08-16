package netpolicy

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// writeTestTemplate writes YAML content to a temp file and returns the directory.
func writeTestTemplate(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDenyProductionDelete(t *testing.T) {
	yaml := `
id: k8s/deny-production-destructive
info:
  name: Block destructive ops in production
  author: agentjail
  severity: critical
  tags: [kubernetes, production, safety]
match:
  service: [kubernetes]
  verb: [delete, patch]
  namespace: [production, prod, "prod-*"]
action: deny
reason: "Blocked {{.Verb}} on {{.ResourceType}}/{{.ResourceName}} in {{.Namespace}}"
impact: "Would {{.Verb}} {{.ResourceType}}/{{.ResourceName}} in production namespace"
`
	dir := writeTestTemplate(t, "k8s.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	op := &Operation{
		Service:      "kubernetes",
		Verb:         "delete",
		ResourceType: "pods",
		ResourceName: "web-frontend-abc123",
		Namespace:    "production",
	}
	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected action deny, got %s", result.Action)
	}
	if result.Template.ID != "k8s/deny-production-destructive" {
		t.Errorf("unexpected template ID: %s", result.Template.ID)
	}
}

func TestMatchHTTPHostAndPort(t *testing.T) {
	dir := writeTestTemplate(t, "http.yaml", `
id: deny-http-control
info:
  name: Block cleartext HTTP control
match:
  protocol: [http]
  host: [www.cloudflare.com]
  port: [80]
action: deny
reason: cleartext HTTP denied
`)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodGet, "http://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		t.Fatal(err)
	}
	op := RecognizeHTTPAt("www.cloudflare.com", Port(80), request, nil)
	if result := m.Evaluate(op); result == nil || result.Template.ID != "deny-http-control" {
		t.Fatalf("HTTP host+port policy did not match: %#v", result)
	}
	op.Port = Port(443)
	if result := m.Evaluate(op); result != nil {
		t.Fatalf("port-80 policy matched port 443: %#v", result)
	}
}

func TestGetDoesNotMatchDeleteTemplate(t *testing.T) {
	yaml := `
id: k8s/deny-production-destructive
info:
  name: Block destructive ops in production
  author: agentjail
  severity: critical
  tags: [kubernetes, production, safety]
match:
  service: [kubernetes]
  verb: [delete, patch]
  namespace: [production]
action: deny
reason: "Blocked {{.Verb}}"
`
	dir := writeTestTemplate(t, "k8s.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	op := &Operation{
		Service:      "kubernetes",
		Verb:         "get",
		ResourceType: "pods",
		Namespace:    "production",
	}
	result := m.Evaluate(op)
	if result != nil {
		t.Errorf("expected no match for GET, got action=%s", result.Action)
	}
}

func TestPIIScanDetectsSSN(t *testing.T) {
	yaml := `
id: pii/block-outbound-ssn
info:
  name: Block SSN in outbound requests
  author: agentjail
  severity: critical
  tags: [pii, compliance]
match:
  service: [anthropic, openai]
scan:
  payload:
    - type: regex
      name: SSN
      patterns: ['\b\d{3}-\d{2}-\d{4}\b']
action: deny
reason: "PII detected in outbound request"
`
	dir := writeTestTemplate(t, "pii.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	op := &Operation{
		Service: "anthropic",
		Payload: map[string]any{
			"messages": []any{
				map[string]any{
					"content": "The SSN is 123-45-6789 and we need to process it",
				},
			},
		},
	}
	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("expected deny result for SSN, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %s", result.Action)
	}
	if len(result.ScanHits) == 0 {
		t.Fatal("expected scan hits for SSN")
	}
	if result.ScanHits[0].RuleName != "SSN" {
		t.Errorf("expected rule name SSN, got %s", result.ScanHits[0].RuleName)
	}
}

func TestMostRestrictiveWins(t *testing.T) {
	yaml := `
id: allow-all
info:
  name: Allow everything
  author: agentjail
  severity: info
  tags: [baseline]
match: {}
action: allow
reason: "Default allow"
---
id: deny-delete
info:
  name: Block deletes
  author: agentjail
  severity: high
  tags: [safety]
match:
  verb: [delete]
action: deny
reason: "Delete blocked"
`
	dir := writeTestTemplate(t, "multi.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	// DELETE should match both, but deny wins.
	op := &Operation{Verb: "delete"}
	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny (most restrictive), got %s", result.Action)
	}

	// GET should only match allow-all.
	op2 := &Operation{Verb: "get"}
	result2 := m.Evaluate(op2)
	if result2 == nil {
		t.Fatal("expected allow result, got nil")
	}
	if result2.Action != "allow" {
		t.Errorf("expected allow, got %s", result2.Action)
	}
}

func TestGlobMatchingOnNamespace(t *testing.T) {
	yaml := `
id: k8s/deny-prod-glob
info:
  name: Deny prod glob
  author: agentjail
  severity: critical
  tags: [kubernetes]
match:
  namespace: ["prod*"]
action: deny
reason: "Blocked in {{.Namespace}}"
`
	dir := writeTestTemplate(t, "glob.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ns    string
		match bool
	}{
		{"production", true},
		{"prod", true},
		{"prod-us-east", true},
		{"staging", false},
		{"dev", false},
	}

	for _, tc := range tests {
		op := &Operation{Namespace: tc.ns}
		result := m.Evaluate(op)
		if tc.match && result == nil {
			t.Errorf("expected match for namespace %q, got nil", tc.ns)
		}
		if !tc.match && result != nil {
			t.Errorf("expected no match for namespace %q, got action=%s", tc.ns, result.Action)
		}
	}
}

func TestRegexMatchingOnPath(t *testing.T) {
	yaml := `
id: k8s/path-regex
info:
  name: Match K8s pod paths
  author: agentjail
  severity: high
  tags: [kubernetes]
match:
  path: ["re:/api/v1/namespaces/.*/pods"]
action: ask
reason: "Pod access detected on {{.Path}}"
`
	dir := writeTestTemplate(t, "regex.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path  string
		match bool
	}{
		{"/api/v1/namespaces/production/pods", true},
		{"/api/v1/namespaces/default/pods/my-pod", true},
		{"/api/v1/nodes", false},
		{"/healthz", false},
	}

	for _, tc := range tests {
		op := &Operation{Path: tc.path}
		result := m.Evaluate(op)
		if tc.match && result == nil {
			t.Errorf("expected match for path %q, got nil", tc.path)
		}
		if !tc.match && result != nil {
			t.Errorf("expected no match for path %q, got action=%s", tc.path, result.Action)
		}
	}
}

func TestEmptyMatchSpecMatchesEverything(t *testing.T) {
	yaml := `
id: catch-all
info:
  name: Catch all
  author: agentjail
  severity: info
  tags: [baseline]
match: {}
action: allow
reason: "Catch-all"
`
	dir := writeTestTemplate(t, "catchall.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	op := &Operation{
		Service:   "anything",
		Verb:      "whatever",
		Namespace: "random",
		Path:      "/some/path",
	}
	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("expected match for catch-all, got nil")
	}
	if result.Action != "allow" {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestTemplateVariableExpansion(t *testing.T) {
	yaml := `
id: test/expand
info:
  name: Variable expansion test
  author: agentjail
  severity: high
  tags: [test]
match:
  verb: [delete]
action: deny
reason: "Blocked {{.Verb}} on {{.ResourceType}}/{{.ResourceName}} in {{.Namespace}} ({{.Service}})"
impact: "Would {{.Verb}} {{.ResourceType}} via {{.Method}} {{.Path}}"
`
	dir := writeTestTemplate(t, "expand.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	op := &Operation{
		Service:      "kubernetes",
		Verb:         "delete",
		ResourceType: "pods",
		ResourceName: "web-123",
		Namespace:    "production",
		Method:       "DELETE",
		Path:         "/api/v1/namespaces/production/pods/web-123",
	}
	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	expectedReason := "Blocked delete on pods/web-123 in production (kubernetes)"
	if result.Reason != expectedReason {
		t.Errorf("reason mismatch:\n  got:  %s\n  want: %s", result.Reason, expectedReason)
	}

	expectedImpact := "Would delete pods via DELETE /api/v1/namespaces/production/pods/web-123"
	if result.Impact != expectedImpact {
		t.Errorf("impact mismatch:\n  got:  %s\n  want: %s", result.Impact, expectedImpact)
	}
}

func TestLoadSeedTemplates(t *testing.T) {
	// Verify that the seed template packs parse without error.
	// This test assumes you run it from the repo root or adjust the path.
	packsDir := findPacksDir(t)
	if packsDir == "" {
		t.Skip("packs directory not found")
	}

	templates, err := LoadTemplates(packsDir)
	if err != nil {
		t.Fatalf("failed to load seed templates: %v", err)
	}
	if len(templates) == 0 {
		t.Fatal("expected at least one seed template")
	}

	// Check we loaded templates from multi-document files.
	ids := make(map[string]bool)
	for _, tmpl := range templates {
		ids[tmpl.ID] = true
	}

	expected := []string{
		"k8s/deny-production-destructive",
		"k8s/ask-production-write",
		"pii/block-outbound-ssn",
		"db/deny-ddl",
		"db/ask-delete",
		"ssh/baseline",
		"ssh/deny-prod",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected seed template %q not found", id)
		}
	}
}

// findPacksDir walks up from the current directory to find agentpolicy/packs.
func findPacksDir(t *testing.T) string {
	t.Helper()
	// Try relative paths from test working directory.
	candidates := []string{
		"../../agentpolicy/packs",
		"../agentpolicy/packs",
		"agentpolicy/packs",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}
