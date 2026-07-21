package tunnel

import (
	"encoding/base64"
	"math"
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

// makeValidKey returns a base64-encoded WireGuard key of the given byte length.
// It uses all-zero bytes (structurally valid base64, wrong length if not 32).
func makeKeyBytes(n int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, n))
}

// chaosValidConfig returns a fully valid Config for use as a baseline.
func chaosValidConfig(t *testing.T) Config {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return Config{
		PrivateKey:    priv,
		ListenPort:    51820,
		PeerPublicKey: pub,
		TunnelAddr:    "10.78.0.1/16",
	}
}

// ---------------------------------------------------------------------------
// 1. Port boundary tests
// ---------------------------------------------------------------------------

func TestChaosPortBoundaries(t *testing.T) {
	type portCase struct {
		port    int
		wantErr bool
		desc    string
	}
	cases := []portCase{
		{0, false, "port 0 (zero, OS-assigned)"},
		{65535, false, "port 65535 (max valid)"},
		{65536, true, "port 65536 (one above max)"},
		{-1, true, "port -1 (negative)"},
		{math.MaxInt, true, "port MaxInt"},
		{1, false, "port 1 (min valid)"},
	}

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			cfg := Config{
				PrivateKey:    priv,
				ListenPort:    tc.port,
				PeerPublicKey: pub,
				TunnelAddr:    "10.78.0.1/16",
			}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %s, got nil", tc.desc)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error for %s, got: %v", tc.desc, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. Private key wrong-length (valid base64, wrong byte count)
// ---------------------------------------------------------------------------

func TestChaosPrivateKeyWrongLength(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	type keyCase struct {
		name    string
		keyB64  string
		wantErr bool
	}

	cases := []keyCase{
		{"31-byte key", makeKeyBytes(31), true},
		{"33-byte key", makeKeyBytes(33), true},
		// 0-byte key encodes to "", which triggers the "required" check first
		{"0-byte key (empty base64)", makeKeyBytes(0), true},
		{"64-byte key (double-length)", makeKeyBytes(64), true},
		{"32-byte key (correct length)", makeKeyBytes(32), false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				PrivateKey:    tc.keyB64,
				ListenPort:    51820,
				PeerPublicKey: pub,
				TunnelAddr:    "10.78.0.1/16",
			}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error for %s, got: %v", tc.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Public key invalid base64 characters
// ---------------------------------------------------------------------------

func TestChaosPublicKeyInvalidBase64(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cases := []struct {
		name   string
		pubKey string
	}{
		{"space in key", "abc def=="},
		{"exclamation mark", "abc!def="},
		{"null byte embedded", "abc\x00def="},
		{"unicode rune", "abcédef="},
		{"all non-base64 chars", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!="},
		{"url-safe base64 (wrong alphabet)", "aGVsbG8td29ybGQ-"},
		{"tab character", "abc\tdef="},
		{"newline embedded", "abc\ndef="},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				PrivateKey:    priv,
				ListenPort:    51820,
				PeerPublicKey: tc.pubKey,
				TunnelAddr:    "10.78.0.1/16",
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected error for public key %q, got nil", tc.pubKey)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Tunnel address varieties
// ---------------------------------------------------------------------------

func TestChaosTunnelAddresses(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	type addrCase struct {
		addr    string
		wantErr bool
		desc    string
	}
	cases := []addrCase{
		// Valid CIDRs (netip.ParsePrefix accepts these)
		{"0.0.0.0/0", false, "default route 0.0.0.0/0"},
		{"255.255.255.255/32", false, "broadcast host /32"},
		{"::1/128", false, "IPv6 loopback ::1/128"},
		{"10.0.0.0/8", false, "RFC-1918 class A"},
		{"192.168.1.1/24", false, "RFC-1918 with host bits"},
		// Invalid CIDRs
		{"not-a-cidr", true, "garbage string"},
		{"10.0.0.1", true, "IP without prefix length"},
		{"10.0.0.1/33", true, "prefix length out of range /33"},
		{"300.1.2.3/24", true, "octet out of range"},
		{"/24", true, "missing address"},
		{"10.0.0.1/", true, "missing prefix length"},
		{"", true, "empty string"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			cfg := Config{
				PrivateKey:    priv,
				ListenPort:    51820,
				PeerPublicKey: pub,
				TunnelAddr:    tc.addr,
			}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for addr %q, got nil", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error for addr %q, got: %v", tc.addr, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. Empty string for every field individually
// ---------------------------------------------------------------------------

func TestChaosEmptyFields(t *testing.T) {
	base := chaosValidConfig(t)

	// PrivateKey empty
	t.Run("empty PrivateKey", func(t *testing.T) {
		cfg := base
		cfg.PrivateKey = ""
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for empty PrivateKey, got nil")
		}
	})

	// PeerPublicKey empty
	t.Run("empty PeerPublicKey", func(t *testing.T) {
		cfg := base
		cfg.PeerPublicKey = ""
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for empty PeerPublicKey, got nil")
		}
	})

	// TunnelAddr empty
	t.Run("empty TunnelAddr", func(t *testing.T) {
		cfg := base
		cfg.TunnelAddr = ""
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for empty TunnelAddr, got nil")
		}
	})

	// ListenPort zero (int zero-value == 0) means OS-assigned, not invalid.
	t.Run("zero ListenPort is OS-assigned", func(t *testing.T) {
		cfg := base
		cfg.ListenPort = 0
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error for zero ListenPort (OS-assigned), got: %v", err)
		}
	})

	// PacksDir empty — not validated, should NOT cause an error
	t.Run("empty PacksDir (no validation expected)", func(t *testing.T) {
		cfg := base
		cfg.PacksDir = ""
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error for empty PacksDir: %v", err)
		}
	})

	// All fields empty simultaneously
	t.Run("all fields empty", func(t *testing.T) {
		cfg := Config{}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for fully empty Config, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// 6. GenerateKeyPair 1000 times — uniqueness and validity
// ---------------------------------------------------------------------------

func TestChaosGenerateKeyPairUniqueness(t *testing.T) {
	const n = 1000
	privKeys := make(map[string]struct{}, n)
	pubKeys := make(map[string]struct{}, n)

	for i := 0; i < n; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("iteration %d: GenerateKeyPair error: %v", i, err)
		}

		// Validate private key bytes
		privB, err := base64.StdEncoding.DecodeString(priv)
		if err != nil {
			t.Fatalf("iteration %d: private key base64 decode: %v", i, err)
		}
		if len(privB) != device.NoisePrivateKeySize {
			t.Fatalf("iteration %d: private key length = %d, want %d", i, len(privB), device.NoisePrivateKeySize)
		}
		// WireGuard clamping invariants
		if privB[0]&7 != 0 {
			t.Errorf("iteration %d: private key low 3 bits not cleared", i)
		}
		if privB[31]&128 != 0 {
			t.Errorf("iteration %d: private key high bit not cleared", i)
		}
		if privB[31]&64 == 0 {
			t.Errorf("iteration %d: private key bit 254 not set", i)
		}

		// Validate public key bytes
		pubB, err := base64.StdEncoding.DecodeString(pub)
		if err != nil {
			t.Fatalf("iteration %d: public key base64 decode: %v", i, err)
		}
		if len(pubB) != device.NoisePublicKeySize {
			t.Fatalf("iteration %d: public key length = %d, want %d", i, len(pubB), device.NoisePublicKeySize)
		}

		// Uniqueness
		if _, dup := privKeys[priv]; dup {
			t.Fatalf("iteration %d: duplicate private key generated", i)
		}
		if _, dup := pubKeys[pub]; dup {
			t.Fatalf("iteration %d: duplicate public key generated", i)
		}

		privKeys[priv] = struct{}{}
		pubKeys[pub] = struct{}{}
	}

	t.Logf("generated %d key pairs, all unique and valid", n)
}

// ---------------------------------------------------------------------------
// 7. MTU values
// ---------------------------------------------------------------------------

func TestChaosMTUValues(t *testing.T) {
	type mtuCase struct {
		mtu     int
		wantMTU int
		desc    string
	}
	cases := []mtuCase{
		{0, device.DefaultMTU, "MTU 0 → default (1420)"},
		{1, 1, "MTU 1 (minimum possible)"},
		{68, 68, "MTU 68 (IPv4 minimum for PMTUD)"},
		{1500, 1500, "MTU 1500 (Ethernet standard)"},
		{9000, 9000, "MTU 9000 (jumbo frames)"},
		{65535, 65535, "MTU 65535 (theoretical max)"},
		{-1, device.DefaultMTU, "MTU -1 (negative → default)"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			cfg := Config{MTU: tc.mtu}
			got := cfg.mtu()
			if got != tc.wantMTU {
				t.Errorf("mtu() = %d, want %d for MTU=%d", got, tc.wantMTU, tc.mtu)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. Valid config → corrupt one field at a time
// ---------------------------------------------------------------------------

func TestChaosCorruptOneFieldAtATime(t *testing.T) {
	base := chaosValidConfig(t)

	// Sanity check: base config must be valid.
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline config is invalid: %v", err)
	}

	corruptors := []struct {
		name   string
		mutate func(*Config)
	}{
		{"corrupt PrivateKey to garbage", func(c *Config) { c.PrivateKey = "!!!not-base64!!!" }},
		{"corrupt PrivateKey to wrong-length", func(c *Config) { c.PrivateKey = makeKeyBytes(16) }},
		{"corrupt PrivateKey to empty", func(c *Config) { c.PrivateKey = "" }},
		{"corrupt PeerPublicKey to garbage", func(c *Config) { c.PeerPublicKey = "!!!not-base64!!!" }},
		{"corrupt PeerPublicKey to wrong-length", func(c *Config) { c.PeerPublicKey = makeKeyBytes(1) }},
		{"corrupt PeerPublicKey to empty", func(c *Config) { c.PeerPublicKey = "" }},
		// ListenPort 0 is deliberately excluded here: it means OS-assigned,
		// not corrupt (see TestChaosPortBoundaries's "port 0" case).
		{"corrupt ListenPort to -1", func(c *Config) { c.ListenPort = -1 }},
		{"corrupt ListenPort to 65536", func(c *Config) { c.ListenPort = 65536 }},
		{"corrupt ListenPort to MaxInt", func(c *Config) { c.ListenPort = math.MaxInt }},
		{"corrupt TunnelAddr to empty", func(c *Config) { c.TunnelAddr = "" }},
		{"corrupt TunnelAddr to bare IP", func(c *Config) { c.TunnelAddr = "10.0.0.1" }},
		{"corrupt TunnelAddr to garbage", func(c *Config) { c.TunnelAddr = "GARBAGE" }},
	}

	for _, cor := range corruptors {
		cor := cor
		t.Run(cor.name, func(t *testing.T) {
			cfg := base // copy
			cor.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected validation error after '%s', got nil", cor.name)
			}
		})
	}
}
