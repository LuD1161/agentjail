package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

func upstreamTLSConfig(_ *httptest.Server) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

func TestMITMPolicyDeny(t *testing.T) {
	// Start a real HTTPS upstream server.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach here"))
	}))
	defer upstream.Close()

	// Generate a CA for MITM.
	caDir := t.TempDir()
	caCert, caKey, err := GenerateCA(caDir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Write a deny-all template.
	packDir := t.TempDir()
	tmplContent := `id: deny-all-test
info:
  name: Deny All Test
  severity: critical
  author: test
match:
  protocol:
    - http
action: deny
reason: "blocked by test policy"
`
	if err := os.WriteFile(filepath.Join(packDir, "deny.yaml"), []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	matcher, err := netpolicy.NewMatcher(packDir)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	var lastLog *RequestLog
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewMITMHandler(caCert, caKey, logger, func(rl *RequestLog) {
		lastLog = rl
	})
	handler.Matcher = matcher
	handler.UpstreamTLSConfig = upstreamTLSConfig(upstream)

	// Create a pipe pair to simulate client <-> MITM.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Parse upstream host:port (strip scheme).
	upstreamAddr := strings.TrimPrefix(upstream.URL, "https://")
	_, port, _ := net.SplitHostPort(upstreamAddr)
	host := "localhost"

	// Run MITM handler in background.
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.Handle(serverConn, host, port)
	}()

	// Client side: TLS handshake with the MITM (trusting our CA).
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	// Send a GET request.
	req, _ := http.NewRequest("GET", "https://"+upstreamAddr+"/test", nil)
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read the response.
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
	if denyHeader := resp.Header.Get("X-Agentjail-Deny"); denyHeader != "deny-all-test" {
		t.Errorf("expected X-Agentjail-Deny=deny-all-test, got %q", denyHeader)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "blocked by agentjail network policy") {
		t.Errorf("deny body should contain policy message, got: %s", body)
	}

	// Close client to let handler finish.
	clientTLS.Close()
	<-done

	if lastLog == nil {
		t.Fatal("expected a RequestLog to be emitted")
	}
	if lastLog.PolicyAction != "deny" {
		t.Errorf("expected PolicyAction=deny, got %q", lastLog.PolicyAction)
	}
	if lastLog.PolicyTemplate != "deny-all-test" {
		t.Errorf("expected PolicyTemplate=deny-all-test, got %q", lastLog.PolicyTemplate)
	}
	if lastLog.StatusCode != 403 {
		t.Errorf("expected StatusCode=403, got %d", lastLog.StatusCode)
	}
}

func TestMITMPolicyAllow(t *testing.T) {
	// Start a real HTTPS upstream server.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream OK"))
	}))
	defer upstream.Close()

	// Generate a CA for MITM.
	caDir := t.TempDir()
	caCert, caKey, err := GenerateCA(caDir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Write an allow-all template.
	packDir := t.TempDir()
	tmplContent := `id: allow-all-test
info:
  name: Allow All Test
  severity: info
  author: test
match:
  protocol:
    - http
action: allow
reason: "allowed by test policy"
`
	if err := os.WriteFile(filepath.Join(packDir, "allow.yaml"), []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	matcher, err := netpolicy.NewMatcher(packDir)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	var lastLog *RequestLog
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewMITMHandler(caCert, caKey, logger, func(rl *RequestLog) {
		lastLog = rl
	})
	handler.Matcher = matcher
	handler.UpstreamTLSConfig = upstreamTLSConfig(upstream)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	upstreamAddr := strings.TrimPrefix(upstream.URL, "https://")
	_, port, _ := net.SplitHostPort(upstreamAddr)
	host := "localhost"

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.Handle(serverConn, host, port)
	}()

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://"+upstreamAddr+"/test", nil)
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream OK" {
		t.Errorf("expected upstream body, got: %s", body)
	}

	clientTLS.Close()
	<-done

	if lastLog == nil {
		t.Fatal("expected a RequestLog to be emitted")
	}
	if lastLog.PolicyAction != "allow" {
		t.Errorf("expected PolicyAction=allow, got %q", lastLog.PolicyAction)
	}
	if lastLog.Service == "" {
		t.Error("expected Service to be populated by recognizer")
	}
}
