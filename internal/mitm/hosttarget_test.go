package mitm

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestParseHostTarget(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		wantHost string
		wantIP   bool
	}{
		{"example.com", "example.com", false},
		{"example.com:443", "example.com", false},
		{"EXAMPLE.COM", "example.com", false},
		{"example.com:8443", "example.com", false},
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4:443", "1.2.3.4", true},
		{"[::1]", "::1", true},
		{"[::1]:443", "::1", true},
		{"::1", "::1", true},
		// Canonicalized, so one address written two ways is one cache key.
		{"[2001:0db8:0000:0000:0000:0000:0000:0001]", "2001:db8::1", true},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got := ParseHostTarget(tc.raw)
			if got.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tc.wantHost)
			}
			if got.IsIP() != tc.wantIP {
				t.Errorf("IsIP() = %v, want %v", got.IsIP(), tc.wantIP)
			}
		})
	}
}

func TestDialAddrRebracketsIPv6(t *testing.T) {
	if got := ParseHostTarget("[::1]:443").DialAddr("443"); got != "[::1]:443" {
		t.Errorf("DialAddr = %q, want %q", got, "[::1]:443")
	}
	if got := ParseHostTarget("example.com").DialAddr("443"); got != "example.com:443" {
		t.Errorf("DialAddr = %q, want %q", got, "example.com:443")
	}
}

// The defect: an IP literal landed in DNSNames, which no verifier accepts for
// an IP connection, so every https://<ip> request failed under interception.
// AGE-220.
func TestSignHostCertPutsIPsInIPSANs(t *testing.T) {
	ca, caKey, _, err := GenerateCAInMemory()
	if err != nil {
		t.Fatalf("GenerateCAInMemory: %v", err)
	}

	for _, tc := range []struct {
		host    string
		wantIP  string // non-empty => expect this IP SAN
		wantDNS string // non-empty => expect this DNS SAN
	}{
		{host: "example.com", wantDNS: "example.com"},
		{host: "1.2.3.4", wantIP: "1.2.3.4"},
		{host: "1.2.3.4:443", wantIP: "1.2.3.4"},
		{host: "[::1]", wantIP: "::1"},
		{host: "::1", wantIP: "::1"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			tlsCert, err := SignHostCert(ca, caKey, tc.host)
			if err != nil {
				t.Fatalf("SignHostCert: %v", err)
			}
			leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
			if err != nil {
				t.Fatalf("parse leaf: %v", err)
			}

			if tc.wantIP != "" {
				if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP(tc.wantIP)) {
					t.Fatalf("IPAddresses = %v, want [%s]", leaf.IPAddresses, tc.wantIP)
				}
				if len(leaf.DNSNames) != 0 {
					t.Errorf("DNSNames = %v, want none for an IP target", leaf.DNSNames)
				}
				// The property that actually matters: Go accepts the cert for
				// the IP connection.
				if err := leaf.VerifyHostname(tc.wantIP); err != nil {
					t.Errorf("VerifyHostname(%s) = %v, want nil", tc.wantIP, err)
				}
			} else {
				if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != tc.wantDNS {
					t.Fatalf("DNSNames = %v, want [%s]", leaf.DNSNames, tc.wantDNS)
				}
				if len(leaf.IPAddresses) != 0 {
					t.Errorf("IPAddresses = %v, want none for a DNS target", leaf.IPAddresses)
				}
				if err := leaf.VerifyHostname(tc.wantDNS); err != nil {
					t.Errorf("VerifyHostname(%s) = %v, want nil", tc.wantDNS, err)
				}
			}
		})
	}
}
