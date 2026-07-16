package mitm

import (
	"net"
	"strings"
)

// HostTarget is a connection target parsed once, so the cert, the SNI, the dial
// address, the cache key and the policy host cannot disagree about what "host"
// means. Callers hand us a host from several paths (SNI, the DNS-VIP registry,
// the generic fallback) and not all of them agree on whether a port or IPv6
// brackets are included. AGE-220.
type HostTarget struct {
	// Host is the bare host: a lowercased DNS name, or an IP literal in its
	// canonical form with no brackets. Never carries a port.
	Host string

	// IP is non-nil exactly when Host is an IP literal. An IP target needs an
	// IP SAN on the leaf; a DNS SAN is not accepted for an IP connection
	// (RFC 6125, Go's x509.Certificate.VerifyHostname).
	IP net.IP
}

// IsIP reports whether the target is an IP literal rather than a DNS name.
func (t HostTarget) IsIP() bool { return t.IP != nil }

// ParseHostTarget normalizes a host that may arrive as any of:
//
//	example.com      example.com:443
//	1.2.3.4          1.2.3.4:443
//	[::1]            [::1]:443        ::1
//
// A port, if present, is discarded: the caller already knows the port it
// dialed, and smuggling it inside the host string is what makes `host:`
// templates miss (AGE-217).
func ParseHostTarget(raw string) HostTarget {
	h := strings.TrimSpace(raw)

	// Strip a port if there is one. SplitHostPort also unwraps the brackets of
	// a "[::1]:443" form for us.
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	} else if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		// Bracketed IPv6 with no port: SplitHostPort rejects it.
		h = h[1 : len(h)-1]
	}

	if ip := net.ParseIP(h); ip != nil {
		// ip.String() canonicalizes (e.g. compresses zero runs), so the same
		// address written two ways yields one cache key and one SAN.
		return HostTarget{Host: ip.String(), IP: ip}
	}

	return HostTarget{Host: strings.ToLower(h)}
}

// DialAddr returns the address to dial, re-bracketing IPv6 as needed.
func (t HostTarget) DialAddr(port string) string {
	return net.JoinHostPort(t.Host, port)
}
