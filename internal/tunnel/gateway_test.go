package tunnel

import (
	"encoding/base64"
	"net"
	"testing"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/netpolicy"
	"golang.zx2c4.com/wireguard/device"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	// Decode and check sizes.
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("private key base64 decode: %v", err)
	}
	if len(privBytes) != device.NoisePrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(privBytes), device.NoisePrivateKeySize)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("public key base64 decode: %v", err)
	}
	if len(pubBytes) != device.NoisePublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pubBytes), device.NoisePublicKeySize)
	}

	// Clamping checks.
	if privBytes[0]&7 != 0 {
		t.Error("private key low 3 bits not cleared (clamping)")
	}
	if privBytes[31]&128 != 0 {
		t.Error("private key high bit not cleared (clamping)")
	}
	if privBytes[31]&64 == 0 {
		t.Error("private key bit 254 not set (clamping)")
	}

	// Two calls should produce different keys.
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair() error: %v", err)
	}
	if priv == priv2 {
		t.Error("two key generations produced the same private key")
	}
	if pub == pub2 {
		t.Error("two key generations produced the same public key")
	}
}

func TestConfigValidate(t *testing.T) {
	// Generate valid keys for the tests.
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	valid := Config{
		PrivateKey:    priv,
		ListenPort:    51820,
		PeerPublicKey: pub,
		TunnelAddr:    "10.78.0.1/16",
	}

	t.Run("valid config", func(t *testing.T) {
		if err := valid.Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("missing private key", func(t *testing.T) {
		cfg := valid
		cfg.PrivateKey = ""
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing private key")
		}
	})

	t.Run("invalid private key", func(t *testing.T) {
		cfg := valid
		cfg.PrivateKey = "not-valid-base64!!"
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for invalid private key")
		}
	})

	t.Run("wrong size private key", func(t *testing.T) {
		cfg := valid
		cfg.PrivateKey = base64.StdEncoding.EncodeToString([]byte("tooshort"))
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for wrong-size private key")
		}
	})

	t.Run("missing peer public key", func(t *testing.T) {
		cfg := valid
		cfg.PeerPublicKey = ""
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing peer public key")
		}
	})

	t.Run("listen port zero is OS-assigned, not invalid", func(t *testing.T) {
		cfg := valid
		cfg.ListenPort = 0
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error for port 0 (OS-assigned), got: %v", err)
		}
	})

	t.Run("invalid listen port negative", func(t *testing.T) {
		cfg := valid
		cfg.ListenPort = -1
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for negative port")
		}
	})

	t.Run("invalid listen port too high", func(t *testing.T) {
		cfg := valid
		cfg.ListenPort = 70000
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for port 70000")
		}
	})

	t.Run("missing tunnel addr", func(t *testing.T) {
		cfg := valid
		cfg.TunnelAddr = ""
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing tunnel address")
		}
	})

	t.Run("invalid tunnel addr", func(t *testing.T) {
		cfg := valid
		cfg.TunnelAddr = "not-an-address"
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for invalid tunnel address")
		}
	})
}

func TestConfigMTU(t *testing.T) {
	cfg := Config{MTU: 0}
	if got := cfg.mtu(); got != device.DefaultMTU {
		t.Errorf("default mtu() = %d, want %d", got, device.DefaultMTU)
	}

	cfg.MTU = 1500
	if got := cfg.mtu(); got != 1500 {
		t.Errorf("custom mtu() = %d, want 1500", got)
	}
}

func TestBuildIPC(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := Config{
		PrivateKey:    priv,
		ListenPort:    51820,
		PeerPublicKey: pub,
	}

	ipc, err := buildIPC(cfg)
	if err != nil {
		t.Fatalf("buildIPC error: %v", err)
	}

	// Check that the IPC string contains the expected fields.
	if len(ipc) == 0 {
		t.Error("IPC string is empty")
	}
	// Should contain private_key, listen_port, public_key, allowed_ip.
	for _, want := range []string{"private_key=", "listen_port=51820", "public_key=", "allowed_ip=0.0.0.0/0"} {
		if !contains(ipc, want) {
			t.Errorf("IPC string missing %q", want)
		}
	}
}

func TestVIPLookupAndRecognize(t *testing.T) {
	reg := dnsvip.NewRegistry()

	// Allocate a VIP for a Postgres host.
	vip, err := reg.Allocate("prod-db.internal")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	// Verify lookup works.
	hostname, ok := reg.Lookup(vip)
	if !ok {
		t.Fatalf("Lookup(%v) returned false", vip)
	}
	if hostname != "prod-db.internal" {
		t.Errorf("Lookup = %q, want %q", hostname, "prod-db.internal")
	}

	// Test RecognizeTCP with a Postgres v3 startup message.
	// Format: int32(length) | int32(version=196608) | "user\0app\0\0"
	pgStartup := buildPGStartup("user", "app")
	op := netpolicy.RecognizeTCP("prod-db.internal", 5432, pgStartup)
	if op == nil {
		t.Fatal("RecognizeTCP returned nil for Postgres data")
	}
	if op.Protocol != "postgres" {
		t.Errorf("Protocol = %q, want %q", op.Protocol, "postgres")
	}
}

func TestRecognizeTCPFallback(t *testing.T) {
	// Create a minimal gateway (just enough for recognizeTCP).
	g := &Gateway{}

	// Unknown port should get a generic TCP operation (not confidently recognized).
	op, recognized := g.recognizeTCP("example.com", 8080, []byte("hello"))
	if op.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", op.Protocol, "tcp")
	}
	if op.Verb != "connect" {
		t.Errorf("Verb = %q, want %q", op.Verb, "connect")
	}
	if recognized {
		t.Errorf("recognized = true for generic fallback, want false")
	}

	// Port 443 should get "tls".
	op, recognized = g.recognizeTCP("example.com", 443, []byte{0x16, 0x03, 0x01})
	if op.Protocol != "tls" {
		t.Errorf("Protocol = %q, want %q for port 443", op.Protocol, "tls")
	}
	if recognized {
		t.Errorf("recognized = true for TLS fallback, want false")
	}

	// Port 80 should get "http".
	op, recognized = g.recognizeTCP("example.com", 80, []byte("GET / HTTP/1.1\r\n"))
	if op.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q for port 80", op.Protocol, "http")
	}
	if recognized {
		t.Errorf("recognized = true for HTTP fallback, want false")
	}
}

func TestNewGateway(t *testing.T) {
	// This test creates a real WireGuard device in userspace (no kernel
	// TUN needed). It verifies the full initialization path.
	gwPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gw): %v", err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	reg := dnsvip.NewRegistry()

	cfg := Config{
		PrivateKey:    gwPriv,
		ListenPort:    51821,
		PeerPublicKey: peerPub,
		TunnelAddr:    "10.78.0.1/16",
	}

	// Should fail validation: TunnelAddr is required.
	badCfg := cfg
	badCfg.TunnelAddr = ""
	_, err = NewGateway(badCfg, reg, nil)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gw.Close()

	if gw.dev == nil {
		t.Error("gateway device is nil")
	}
	// NewGateway now backs the WireGuard device with the promiscuous
	// serverNetstack (accepts SYNs to any destination), not CreateNetTUN's tnet.
	// See ADR 0087-macos-tunnel-promiscuous-gateway.
	if gw.serverNS == nil {
		t.Error("gateway server netstack is nil")
	}
}

// TestNewGateway_ZeroListenPort is the T0.2 acceptance test: ListenPort:0
// (OS-assigned) must construct successfully, and ListenPort() must read back
// the actual bound UDP port from the WireGuard device instead of echoing 0.
func TestNewGateway_ZeroListenPort(t *testing.T) {
	gwPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gw): %v", err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	reg := dnsvip.NewRegistry()
	cfg := Config{
		PrivateKey:    gwPriv,
		ListenPort:    0, // OS-assigned
		PeerPublicKey: peerPub,
		TunnelAddr:    "10.78.0.1/16",
	}

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway with ListenPort:0: %v", err)
	}
	defer gw.Close()

	port := gw.ListenPort()
	if port == 0 {
		t.Fatal("ListenPort() = 0, want the actual OS-assigned bound port")
	}
	if port < 1 || port > 65535 {
		t.Fatalf("ListenPort() = %d, out of valid UDP port range", port)
	}
}

// TestGateway_DNSPacketConn is the T0.3 acceptance test: DNSPacketConn must
// return a usable net.PacketConn bound inside the gateway's netstack, on the
// gateway's own tunnel address, port 53 — the address a host socket cannot
// bind (it's inside the VIP range, not owned by the host kernel).
func TestGateway_DNSPacketConn(t *testing.T) {
	gwPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gw): %v", err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	reg := dnsvip.NewRegistry()
	cfg := Config{
		PrivateKey:    gwPriv,
		ListenPort:    51822,
		PeerPublicKey: peerPub,
		TunnelAddr:    "10.78.0.1/16",
	}

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gw.Close()

	pc := gw.DNSPacketConn()
	if pc == nil {
		t.Fatal("DNSPacketConn() = nil, want a bound net.PacketConn")
	}
	if pc.LocalAddr() == nil {
		t.Fatal("DNSPacketConn().LocalAddr() is nil")
	}

	want := "10.78.0.1:53"
	if got := pc.LocalAddr().String(); got != want {
		t.Errorf("DNSPacketConn().LocalAddr() = %q, want %q", got, want)
	}

	// A forward gateway has no tnet-backed netstack, so DNSPacketConn is nil
	// there (DNS is answered via forwardStack's own dnsResolve callback).
	fwdGw, err := NewForwardGateway(Config{MTU: 1420}, dnsvip.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}
	defer fwdGw.Close()
	if got := fwdGw.DNSPacketConn(); got != nil {
		t.Errorf("forward gateway DNSPacketConn() = %v, want nil", got)
	}
}

func TestRelay(t *testing.T) {
	// Test the bidirectional relay with a pipe pair.
	client, serverSide := net.Pipe()
	upstream, proxySide := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		relay(serverSide, proxySide, nil)
	}()

	// Write from client, read from upstream.
	msg := []byte("hello from client")
	go func() {
		client.Write(msg)
		client.Close()
	}()

	buf := make([]byte, 64)
	n, _ := upstream.Read(buf)
	if string(buf[:n]) != "hello from client" {
		t.Errorf("upstream got %q, want %q", buf[:n], "hello from client")
	}
	upstream.Close()

	<-done
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// buildPGStartup builds a PostgreSQL v3 startup message with the given
// key-value pairs (must be even number of strings).
func buildPGStartup(kvs ...string) []byte {
	// Header: 4 bytes length + 4 bytes version.
	var params []byte
	for _, s := range kvs {
		params = append(params, []byte(s)...)
		params = append(params, 0)
	}
	params = append(params, 0) // final terminator

	length := 4 + 4 + len(params) // length field + version + params
	buf := make([]byte, length)
	buf[0] = byte(length >> 24)
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
	// Version 3.0 = 196608 = 0x00030000
	buf[4] = 0
	buf[5] = 3
	buf[6] = 0
	buf[7] = 0
	copy(buf[8:], params)
	return buf
}
