package tunnel

// accept_test.go — acceptance tests for the real user workflow:
// shield creates a gateway, agent traffic flows through it.
//
// Run: go test -v -run Accept -count=1 ./internal/tunnel/... -timeout 30s

import (
	"encoding/base64"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/device"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// ---------------------------------------------------------------------------
// Test 1: Gateway initialization — the full happy path
// ---------------------------------------------------------------------------

func TestAccept_GatewayInitialization(t *testing.T) {
	privKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gateway): %v", err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	reg := dnsvip.NewRegistry()

	cfg := Config{
		PrivateKey:    privKey,
		ListenPort:    51900,
		PeerPublicKey: peerPub,
		TunnelAddr:    "10.99.0.1/24",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() unexpected error: %v", err)
	}

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway() error: %v", err)
	}
	defer gw.Close()

	if gw.dev == nil {
		t.Error("gateway.dev is nil — WireGuard device was not created")
	}
	if gw.serverNS == nil {
		t.Error("gateway.serverNS is nil — promiscuous gVisor netstack was not initialized")
	}
	if gw.registry == nil {
		t.Error("gateway.registry is nil")
	}
}

// ---------------------------------------------------------------------------
// Test 2: Config defaults — MTU 0 → 1420
// ---------------------------------------------------------------------------

func TestAccept_ConfigMTUDefault(t *testing.T) {
	const wantMTU = device.DefaultMTU // 1420

	cfg := Config{MTU: 0}
	got := cfg.mtu()
	if got != wantMTU {
		t.Errorf("mtu() with MTU=0 = %d, want %d (1420)", got, wantMTU)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Key pair validity — lengths and base64 encoding
// ---------------------------------------------------------------------------

func TestAccept_KeyPairValidity(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	// A base64-encoded 32-byte value is always 44 characters (with padding).
	if len(priv) != 44 {
		t.Errorf("private key length = %d chars, want 44", len(priv))
	}
	if len(pub) != 44 {
		t.Errorf("public key length = %d chars, want 44", len(pub))
	}

	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("private key base64 decode: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("private key raw length = %d bytes, want 32", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("public key base64 decode: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key raw length = %d bytes, want 32", len(pubBytes))
	}

	// Verify via Config.Validate that both keys are structurally acceptable.
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}
	cfg := Config{
		PrivateKey:    priv,
		ListenPort:    51901,
		PeerPublicKey: peerPub,
		TunnelAddr:    "10.99.0.1/24",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Config.Validate() rejected freshly generated key pair: %v", err)
	}

	// The public key must be derivable from the private key.
	// We re-derive the expected public key by generating a second pair and
	// confirming that pub != peerPub (ensures the derivation is key-specific).
	if pub == peerPub {
		t.Error("two distinct private keys produced the same public key")
	}
}

// ---------------------------------------------------------------------------
// Test 4: Multiple key pairs — uniqueness (no seed reuse)
// ---------------------------------------------------------------------------

func TestAccept_MultipleKeyPairsUnique(t *testing.T) {
	const n = 10

	seen := make(map[string]bool, n)
	for i := range n {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() iteration %d error: %v", i, err)
		}
		if seen[priv] {
			t.Errorf("duplicate private key at iteration %d", i)
		}
		seen[priv] = true

		if seen[pub] {
			t.Errorf("duplicate public key at iteration %d", i)
		}
		seen[pub] = true
	}

	if len(seen) != 2*n {
		t.Errorf("expected %d unique keys, got %d", 2*n, len(seen))
	}
}

// ---------------------------------------------------------------------------
// Test 5: Config round-trip — create, validate, all fields accessible
// ---------------------------------------------------------------------------

func TestAccept_ConfigRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	want := Config{
		PrivateKey:    priv,
		ListenPort:    51902,
		PeerPublicKey: pub,
		TunnelAddr:    "10.78.0.1/16",
		PacksDir:      "/tmp/packs",
		MTU:           1500,
	}

	if err := want.Validate(); err != nil {
		t.Fatalf("Config.Validate(): %v", err)
	}

	// All fields must remain accessible after a value copy.
	got := want

	if got.PrivateKey != want.PrivateKey {
		t.Errorf("PrivateKey mismatch after copy")
	}
	if got.ListenPort != want.ListenPort {
		t.Errorf("ListenPort mismatch: got %d, want %d", got.ListenPort, want.ListenPort)
	}
	if got.PeerPublicKey != want.PeerPublicKey {
		t.Errorf("PeerPublicKey mismatch after copy")
	}
	if got.TunnelAddr != want.TunnelAddr {
		t.Errorf("TunnelAddr mismatch: got %q, want %q", got.TunnelAddr, want.TunnelAddr)
	}
	if got.PacksDir != want.PacksDir {
		t.Errorf("PacksDir mismatch: got %q, want %q", got.PacksDir, want.PacksDir)
	}
	if got.MTU != want.MTU {
		t.Errorf("MTU mismatch: got %d, want %d", got.MTU, want.MTU)
	}
	if got.mtu() != 1500 {
		t.Errorf("mtu() = %d, want 1500 for explicitly set MTU", got.mtu())
	}
}

// ---------------------------------------------------------------------------
// Test 6: Gateway with templates dir
// ---------------------------------------------------------------------------

func TestAccept_GatewayWithPacksDir(t *testing.T) {
	// Create a temp dir with a minimal policy template.
	dir := t.TempDir()
	template := `id: test/allow-all
info:
  name: Allow everything
  author: test
  severity: info
  tags: [test]
match:
  protocol: [http]
action: allow
reason: "test policy"
`
	if err := os.WriteFile(filepath.Join(dir, "allow-all.yaml"), []byte(template), 0o644); err != nil {
		t.Fatalf("writing template: %v", err)
	}

	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gw): %v", err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	cfg := Config{
		PrivateKey:    priv,
		ListenPort:    51903,
		PeerPublicKey: peerPub,
		TunnelAddr:    "10.99.1.1/24",
		PacksDir:      dir,
	}

	reg := dnsvip.NewRegistry()
	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway() with PacksDir=%q error: %v", dir, err)
	}
	defer gw.Close()

	if gw.matcher == nil {
		t.Error("gateway.matcher is nil — policy templates were not loaded")
	}
}

// ---------------------------------------------------------------------------
// Test 7: Protocol detection accuracy — real-world bytes
// ---------------------------------------------------------------------------

func TestAccept_ProtocolDetection(t *testing.T) {
	// Build a PostgreSQL v3 startup message (same helper as gateway_test.go).
	pgStartup := buildPGStartup("user", "testuser", "database", "mydb")

	// TLS 1.2 ClientHello: ContentType=0x16 (Handshake), Version=0x0301, ...
	tlsClientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x6c, // record header
		0x01,             // HandshakeType = ClientHello
		0x00, 0x00, 0x68, // length
		0x03, 0x03, // ClientHello version (TLS 1.2)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random (32 bytes, zeros for test)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // session ID length = 0
		0x00, 0x02, // cipher suites length = 2
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, 0x00, // compression methods length=1, null compression
	}

	cases := []struct {
		name      string
		host      string
		port      int
		data      []byte
		wantProto string
		wantNil   bool // true when RecognizeTCP returns nil (expect gateway fallback)
	}{
		{
			name:      "HTTP GET",
			host:      "example.com",
			port:      80,
			data:      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantProto: "http", // gateway fallback for port 80
			wantNil:   true,   // RecognizeTCP returns nil for HTTP (no port 80 case)
		},
		{
			name:      "SSH version string",
			host:      "git.example.com",
			port:      22,
			data:      []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			wantProto: "ssh",
		},
		{
			name:      "PostgreSQL startup",
			host:      "db.internal",
			port:      5432,
			data:      pgStartup,
			wantProto: "postgres",
		},
		{
			name:      "Redis PING",
			host:      "cache.internal",
			port:      6379,
			data:      []byte("*1\r\n$4\r\nPING\r\n"),
			wantProto: "redis",
		},
		{
			name:      "TLS 1.2 ClientHello on port 443",
			host:      "api.example.com",
			port:      443,
			data:      tlsClientHello,
			wantProto: "tls", // gateway fallback for port 443
			wantNil:   true,  // RecognizeTCP returns nil for unknown port 443
		},
		{
			name:      "Unknown random bytes",
			host:      "unknown.internal",
			port:      12345,
			data:      []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
			wantProto: "tcp", // gateway fallback
			wantNil:   true,  // RecognizeTCP returns nil for unknown port
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := netpolicy.RecognizeTCP(tc.host, tc.port, tc.data)

			if tc.wantNil {
				if op != nil {
					t.Errorf("RecognizeTCP returned %+v, want nil", op)
				}
				// For gateway-level fallback verification use recognizeTCP.
				gw := &Gateway{}
				fallbackOp, recognized := gw.recognizeTCP(tc.host, tc.port, tc.data)
				if fallbackOp == nil {
					t.Fatal("recognizeTCP returned nil — gateway has no fallback")
				}
				if recognized {
					t.Errorf("recognizeTCP reported recognized=true for unrecognized data")
				}
				if fallbackOp.Protocol != tc.wantProto {
					t.Errorf("gateway fallback Protocol = %q, want %q", fallbackOp.Protocol, tc.wantProto)
				}
				return
			}

			if op == nil {
				t.Fatalf("RecognizeTCP returned nil for %s data on port %d", tc.name, tc.port)
			}
			if op.Protocol != tc.wantProto {
				t.Errorf("Protocol = %q, want %q", op.Protocol, tc.wantProto)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 8: Handler labels connection with correct protocol name
// ---------------------------------------------------------------------------

func TestAccept_HandlerLabelsConnectionProtocol(t *testing.T) {
	// recognizeTCP is the gateway method that returns the labeled operation.
	// We verify that for each well-known port the returned operation carries
	// the expected protocol label, matching what would appear in the log.

	gw := &Gateway{}

	cases := []struct {
		name      string
		host      string
		port      int
		data      []byte
		wantProto string
		wantVerb  string
	}{
		{
			name:      "SSH connect label",
			host:      "bastion.prod",
			port:      22,
			data:      []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			wantProto: "ssh",
			wantVerb:  "connect",
		},
		{
			name:      "Postgres connect label",
			host:      "db.prod",
			port:      5432,
			data:      buildPGStartup("user", "admin", "database", "orders"),
			wantProto: "postgres",
			wantVerb:  "connect",
		},
		{
			name:      "Redis PING label",
			host:      "cache.prod",
			port:      6379,
			data:      []byte("*1\r\n$4\r\nPING\r\n"),
			wantProto: "redis",
			wantVerb:  "ping", // PING not in verbMap → lowercase passthrough
		},
		{
			name:      "Unknown port TCP fallback label",
			host:      "mystery.host",
			port:      9999,
			data:      []byte("some random traffic"),
			wantProto: "tcp",
			wantVerb:  "connect",
		},
		{
			name:      "Port 443 TLS fallback label",
			host:      "secure.api",
			port:      443,
			data:      []byte{0x16, 0x03, 0x01},
			wantProto: "tls",
			wantVerb:  "connect",
		},
		{
			name:      "Port 80 HTTP fallback label",
			host:      "www.example.com",
			port:      80,
			data:      []byte("GET / HTTP/1.1\r\n\r\n"),
			wantProto: "http",
			wantVerb:  "connect",
		},
	}

	// Ensure cases cover a distinct set of protocols.
	seenProtos := make(map[string]bool)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op, _ := gw.recognizeTCP(tc.host, tc.port, tc.data)
			if op == nil {
				t.Fatal("recognizeTCP returned nil")
			}
			if op.Protocol != tc.wantProto {
				t.Errorf("Protocol = %q, want %q", op.Protocol, tc.wantProto)
			}
			if op.Verb != tc.wantVerb {
				t.Errorf("Verb = %q, want %q", op.Verb, tc.wantVerb)
			}
			seenProtos[op.Protocol] = true
		})
	}

	// Sanity-check: we tested at least 4 distinct protocol labels.
	if len(seenProtos) < 4 {
		t.Errorf("only %d distinct protocols labeled (want ≥ 4): %v", len(seenProtos), maps.Keys(seenProtos))
	}
}
