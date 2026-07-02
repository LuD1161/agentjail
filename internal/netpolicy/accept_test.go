package netpolicy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ── 1. SSH recognizer: OpenSSH 2.0 ─────────────────────────────────────────

func AcceptSSHRecognizer(t *testing.T) {
	data := []byte("SSH-2.0-OpenSSH_9.6\n")
	op := ParseSSHVersion(data, "bastion.example.com:22")

	if op == nil {
		t.Fatal("AcceptSSHRecognizer: expected non-nil Operation, got nil")
	}
	if op.Protocol != "ssh" {
		t.Errorf("Protocol = %q, want %q", op.Protocol, "ssh")
	}
	if op.Service != "ssh" {
		t.Errorf("Service = %q, want %q", op.Service, "ssh")
	}
	if op.Verb != "connect" {
		t.Errorf("Verb = %q, want %q", op.Verb, "connect")
	}

	protoVer, _ := op.Payload["proto_version"].(string)
	if protoVer != "2.0" {
		t.Errorf("proto_version = %q, want %q", protoVer, "2.0")
	}
	version, _ := op.Payload["version"].(string)
	if version != "OpenSSH_9.6" {
		t.Errorf("version = %q, want %q", version, "OpenSSH_9.6")
	}
	software, _ := op.Payload["software"].(string)
	if software != "OpenSSH" {
		t.Errorf("software = %q, want %q", software, "OpenSSH")
	}
	softwareVer, _ := op.Payload["software_version"].(string)
	if softwareVer != "9.6" {
		t.Errorf("software_version = %q, want %q", softwareVer, "9.6")
	}
}

func TestAcceptSSHRecognizer(t *testing.T) { AcceptSSHRecognizer(t) }

// ── 2. SSH recognizer: old version 1.99 ────────────────────────────────────

func AcceptSSHOldVersion(t *testing.T) {
	data := []byte("SSH-1.99-Server\n")
	op := ParseSSHVersion(data, "legacy.host:22")

	if op == nil {
		t.Fatal("AcceptSSHOldVersion: expected non-nil Operation, got nil")
	}
	protoVer, _ := op.Payload["proto_version"].(string)
	if protoVer != "1.99" {
		t.Errorf("proto_version = %q, want %q", protoVer, "1.99")
	}
	// "Server" has no underscore — the full string is the version, name is empty.
	version, _ := op.Payload["version"].(string)
	if version != "Server" {
		t.Errorf("version = %q, want %q", version, "Server")
	}
	softwareVer, _ := op.Payload["software_version"].(string)
	if softwareVer != "Server" {
		t.Errorf("software_version = %q, want %q", softwareVer, "Server")
	}
}

func TestAcceptSSHOldVersion(t *testing.T) { AcceptSSHOldVersion(t) }

// ── 3. PostgreSQL recognizer: startup message protocol 3.0 ─────────────────

func AcceptPostgreSQLRecognizer(t *testing.T) {
	data := buildStartupMessage(map[string]string{
		"user":     "appuser",
		"database": "production_db",
	})
	op := ParsePostgresMessage(data)

	if op == nil {
		t.Fatal("AcceptPostgreSQLRecognizer: expected non-nil Operation, got nil")
	}
	if op.Protocol != "postgres" {
		t.Errorf("Protocol = %q, want %q", op.Protocol, "postgres")
	}
	if op.Service != "postgresql" {
		t.Errorf("Service = %q, want %q", op.Service, "postgresql")
	}
	if op.Verb != "connect" {
		t.Errorf("Verb = %q, want %q", op.Verb, "connect")
	}
	if op.Namespace != "production_db" {
		t.Errorf("Namespace (database) = %q, want %q", op.Namespace, "production_db")
	}
	user, _ := op.Payload["user"].(string)
	if user != "appuser" {
		t.Errorf("payload user = %q, want %q", user, "appuser")
	}
}

func TestAcceptPostgreSQLRecognizer(t *testing.T) { AcceptPostgreSQLRecognizer(t) }

// ── 4. Redis recognizer: PING, GET, SET ────────────────────────────────────

func AcceptRedisRecognizer(t *testing.T) {
	cases := []struct {
		input        string
		wantVerb     string
		wantResource string
	}{
		// PING is not in the known-verb map, so verb == lowercase command name.
		{"PING\r\n", "ping", ""},
		// GET extracts the key.
		{"GET mykey\r\n", "get", "mykey"},
		// SET extracts the key (value is not the resource).
		{"SET mykey myvalue\r\n", "set", "mykey"},
	}

	for _, tc := range cases {
		op := ParseRedisCommand([]byte(tc.input))
		if op == nil {
			t.Fatalf("AcceptRedisRecognizer: ParseRedisCommand(%q) returned nil", tc.input)
		}
		if op.Protocol != "redis" {
			t.Errorf("input %q: Protocol = %q, want %q", tc.input, op.Protocol, "redis")
		}
		if op.Verb != tc.wantVerb {
			t.Errorf("input %q: Verb = %q, want %q", tc.input, op.Verb, tc.wantVerb)
		}
		if op.ResourceName != tc.wantResource {
			t.Errorf("input %q: ResourceName = %q, want %q", tc.input, op.ResourceName, tc.wantResource)
		}
	}
}

func TestAcceptRedisRecognizer(t *testing.T) { AcceptRedisRecognizer(t) }

// ── 5. MongoDB recognizer: OP_MSG with database name ───────────────────────

func AcceptMongoDBRecognizer(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"find", "users"},
		{"$db", "myapp"},
	})
	msg := buildOpMsg(doc)

	op := ParseMongoMessage(msg)
	if op == nil {
		t.Fatal("AcceptMongoDBRecognizer: expected non-nil Operation, got nil")
	}
	if op.Protocol != "mongodb" {
		t.Errorf("Protocol = %q, want %q", op.Protocol, "mongodb")
	}
	if op.Service != "mongodb" {
		t.Errorf("Service = %q, want %q", op.Service, "mongodb")
	}
	if op.Verb != "get" {
		t.Errorf("Verb = %q, want %q", op.Verb, "get")
	}
	if op.ResourceName != "users" {
		t.Errorf("ResourceName = %q, want %q", op.ResourceName, "users")
	}
	// Database name must be present in Namespace.
	if op.Namespace != "myapp" {
		t.Errorf("Namespace (db) = %q, want %q", op.Namespace, "myapp")
	}
}

func TestAcceptMongoDBRecognizer(t *testing.T) { AcceptMongoDBRecognizer(t) }

// ── 6. HTTP recognizer: method, path, Host header ──────────────────────────

func AcceptHTTPRecognizer(t *testing.T) {
	// Simulate: GET /api/v1/repos HTTP/1.1\r\nHost: api.github.com\r\n\r\n
	rawURL := "https://api.github.com/api/v1/repos"
	u, _ := url.Parse(rawURL)
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.URL = u
	req.Header.Set("Host", "api.github.com")

	op := RecognizeHTTP("api.github.com", req, nil)
	if op == nil {
		t.Fatal("AcceptHTTPRecognizer: expected non-nil Operation, got nil")
	}
	if op.Method != http.MethodGet {
		t.Errorf("Method = %q, want %q", op.Method, http.MethodGet)
	}
	if !strings.HasPrefix(op.Path, "/api/v1/repos") {
		t.Errorf("Path = %q, want prefix %q", op.Path, "/api/v1/repos")
	}
	if op.Host != "api.github.com" {
		t.Errorf("Host = %q, want %q", op.Host, "api.github.com")
	}
}

func TestAcceptHTTPRecognizer(t *testing.T) { AcceptHTTPRecognizer(t) }

// ── 7. Template loading: HTTP match rules from YAML ────────────────────────

func AcceptTemplateLoading(t *testing.T) {
	yaml := `
id: http/allow-github-repos
info:
  name: Allow GitHub repo reads
  author: agentjail
  severity: info
  tags: [github, http]
match:
  service: [github]
  verb: [list, get]
action: allow
reason: "Permitted GitHub read on {{.Path}}"
`
	dir := writeTestTemplate(t, "http_allow.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatalf("AcceptTemplateLoading: NewMatcher: %v", err)
	}

	// A GET to /repos should match via the github recognizer.
	req := makeRequest("GET", "https://api.github.com/repos/owner/repo", "", nil)
	op := RecognizeHTTP("api.github.com", req, nil)
	if op == nil {
		t.Fatal("AcceptTemplateLoading: RecognizeHTTP returned nil")
	}

	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("AcceptTemplateLoading: expected template match, got nil")
	}
	if result.Template.ID != "http/allow-github-repos" {
		t.Errorf("Template ID = %q, want %q", result.Template.ID, "http/allow-github-repos")
	}
	if result.Action != "allow" {
		t.Errorf("Action = %q, want %q", result.Action, "allow")
	}
}

func TestAcceptTemplateLoading(t *testing.T) { AcceptTemplateLoading(t) }

// ── 8. Template deny: action:deny blocks matching traffic ──────────────────

func AcceptTemplateDeny(t *testing.T) {
	yaml := `
id: redis/deny-flushall
info:
  name: Block FLUSHALL commands
  author: agentjail
  severity: critical
  tags: [redis, safety]
match:
  service: [redis]
  verb: [admin]
action: deny
reason: "Blocked dangerous Redis admin command"
`
	dir := writeTestTemplate(t, "redis_deny.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatalf("AcceptTemplateDeny: NewMatcher: %v", err)
	}

	op := ParseRedisCommand([]byte("FLUSHALL\r\n"))
	if op == nil {
		t.Fatal("AcceptTemplateDeny: ParseRedisCommand returned nil")
	}

	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("AcceptTemplateDeny: expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("Action = %q, want %q", result.Action, "deny")
	}
}

func TestAcceptTemplateDeny(t *testing.T) { AcceptTemplateDeny(t) }

// ── 9. Template allow: action:allow permits matching traffic ───────────────

func AcceptTemplateAllow(t *testing.T) {
	yaml := `
id: redis/allow-reads
info:
  name: Allow Redis read operations
  author: agentjail
  severity: info
  tags: [redis]
match:
  service: [redis]
  verb: [get]
action: allow
reason: "Permitted Redis read"
`
	dir := writeTestTemplate(t, "redis_allow.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatalf("AcceptTemplateAllow: NewMatcher: %v", err)
	}

	op := ParseRedisCommand([]byte("GET session:abc123\r\n"))
	if op == nil {
		t.Fatal("AcceptTemplateAllow: ParseRedisCommand returned nil")
	}

	result := m.Evaluate(op)
	if result == nil {
		t.Fatal("AcceptTemplateAllow: expected allow result, got nil")
	}
	if result.Action != "allow" {
		t.Errorf("Action = %q, want %q", result.Action, "allow")
	}
}

func TestAcceptTemplateAllow(t *testing.T) { AcceptTemplateAllow(t) }

// ── 10. No matching template: default action is nil ────────────────────────

func AcceptNoMatchingTemplate(t *testing.T) {
	yaml := `
id: k8s/deny-production-delete
info:
  name: Block deletes in production
  author: agentjail
  severity: critical
  tags: [kubernetes, production]
match:
  service: [kubernetes]
  verb: [delete]
  namespace: [production]
action: deny
reason: "Blocked delete in production"
`
	dir := writeTestTemplate(t, "k8s_deny.yaml", yaml)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatalf("AcceptNoMatchingTemplate: NewMatcher: %v", err)
	}

	// A Redis GET doesn't match the k8s template.
	op := ParseRedisCommand([]byte("GET somekey\r\n"))
	if op == nil {
		t.Fatal("AcceptNoMatchingTemplate: ParseRedisCommand returned nil")
	}

	result := m.Evaluate(op)
	if result != nil {
		t.Errorf("AcceptNoMatchingTemplate: expected nil (no match), got action=%s template=%s",
			result.Action, result.Template.ID)
	}
}

func TestAcceptNoMatchingTemplate(t *testing.T) { AcceptNoMatchingTemplate(t) }
