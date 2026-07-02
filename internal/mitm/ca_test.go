package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if caCert == nil {
		t.Fatal("caCert is nil")
	}
	if caKey == nil {
		t.Fatal("caKey is nil")
	}

	// Verify it is a CA.
	if !caCert.IsCA {
		t.Error("expected IsCA=true")
	}
	if caCert.Subject.CommonName != "AgentJail Inspection CA" {
		t.Errorf("unexpected CN: %s", caCert.Subject.CommonName)
	}

	// Verify files on disk.
	certPath := filepath.Join(dir, "root.crt")
	keyPath := filepath.Join(dir, "root.key")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("root.crt not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("root.key not found: %v", err)
	}

	// Verify key permissions.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat root.key: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("root.key permissions = %04o, want 0600", perm)
	}
}

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()

	// First call generates.
	cert1, key1, tlsCert1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}
	if cert1 == nil || key1 == nil || tlsCert1 == nil {
		t.Fatal("first call returned nil")
	}

	// Second call loads from disk.
	cert2, _, _, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}

	// Serial numbers should match (same cert).
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Error("second load returned different cert")
	}
}

func TestSignHostCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostCert, err := SignHostCert(caCert, caKey, "example.com")
	if err != nil {
		t.Fatalf("SignHostCert: %v", err)
	}
	if hostCert == nil {
		t.Fatal("hostCert is nil")
	}

	// Parse and verify the host cert.
	leaf, err := x509.ParseCertificate(hostCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse host cert: %v", err)
	}

	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("host cert CN = %s, want example.com", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("host cert SANs = %v, want [example.com]", leaf.DNSNames)
	}

	// Verify the host cert chains to the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool,
	}); err != nil {
		t.Errorf("host cert does not verify against CA: %v", err)
	}
}

func TestTLSHandshakeWithSignedCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostCert, err := SignHostCert(caCert, caKey, "localhost")
	if err != nil {
		t.Fatalf("SignHostCert: %v", err)
	}

	// Start a TLS server with the signed cert.
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{*hostCert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Server goroutine: accept one connection, write "hello", close.
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("hello"))
		done <- err
	}()

	// Client: trust the CA, connect to the server.
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	addr := ln.Addr().(*net.TCPAddr)
	clientConn, err := tls.Dial("tcp", addr.String(), &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	buf := make([]byte, 5)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want %q", string(buf[:n]), "hello")
	}

	// Wait for server.
	if err := <-done; err != nil {
		t.Errorf("server error: %v", err)
	}
}

func TestHostCertCache(t *testing.T) {
	cache := newHostCertCache()

	// Empty cache returns nil.
	if got := cache.get("example.com"); got != nil {
		t.Error("expected nil for empty cache")
	}

	// Put and get.
	cert := &tls.Certificate{}
	cache.put("example.com", cert)
	if got := cache.get("example.com"); got != cert {
		t.Error("expected to retrieve cached cert")
	}

	// Eviction at capacity.
	cache.maxSize = 5
	for i := 0; i < 10; i++ {
		cache.put(string(rune('a'+i))+".example.com", &tls.Certificate{})
	}
	// After adding 10 entries with max 5, we should have at most 5+1
	// (the last put might trigger eviction bringing it to ~3 then adding 1).
	cache.mu.Lock()
	count := len(cache.certs)
	cache.mu.Unlock()
	if count > 6 {
		t.Errorf("cache has %d entries, expected <= 6 after eviction", count)
	}
}
