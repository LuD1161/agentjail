package dnsvip

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// acceptStartServer starts a DNS server with the supplied registry and returns
// its UDP address and a cancel function. The registry is exposed so acceptance
// tests can verify internal state after DNS round-trips.
func acceptStartServer(t *testing.T, reg *Registry) (addr string, cancel context.CancelFunc) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(pc.LocalAddr().String(), reg)
	srv.PacketConn(pc)

	ctx, cancelFn := context.WithCancel(context.Background())
	go srv.ListenAndServe(ctx)
	time.Sleep(15 * time.Millisecond)

	return pc.LocalAddr().String(), cancelFn
}

// mustBeVIP4 checks that ip is in the 10.78.0.0/16 range.
func mustBeVIP4(t *testing.T, ip net.IP) {
	t.Helper()
	v4 := ip.To4()
	if v4 == nil {
		t.Fatalf("expected IPv4 VIP, got %s", ip)
	}
	if v4[0] != 10 || v4[1] != 78 {
		t.Fatalf("VIP %s is not in 10.78.0.0/16", ip)
	}
}

// mustBeVIP6 checks that ip is in the fd78::/16 range.
func mustBeVIP6(t *testing.T, ip net.IP) {
	t.Helper()
	if ip.To4() != nil {
		t.Fatalf("expected IPv6 VIP, got IPv4-mapped %s", ip)
	}
	if !strings.HasPrefix(ip.String(), "fd78::") {
		t.Fatalf("VIP %s is not in fd78::/16", ip)
	}
}

// TestAcceptFirstResolution verifies that allocating a new hostname for the
// first time returns a VIP in the 10.78.0.0/16 range.
func TestAcceptFirstResolution(t *testing.T) {
	reg := NewRegistry()

	vip, err := reg.Allocate("api.github.com")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	mustBeVIP4(t, vip)
	t.Logf("api.github.com -> %s", vip)
}

// TestAcceptStickyVIP verifies that resolving the same hostname twice returns
// the same VIP (sticky mapping).
func TestAcceptStickyVIP(t *testing.T) {
	reg := NewRegistry()

	vip1, err := reg.Allocate("api.github.com")
	if err != nil {
		t.Fatalf("first Allocate: %v", err)
	}

	vip2, err := reg.Allocate("api.github.com")
	if err != nil {
		t.Fatalf("second Allocate: %v", err)
	}

	if !vip1.Equal(vip2) {
		t.Fatalf("sticky VIP violation: first=%s second=%s", vip1, vip2)
	}
	t.Logf("api.github.com -> %s (stable across two calls)", vip1)
}

// TestAcceptMultipleHostsUniqueVIPs verifies that three different hostnames
// each receive a distinct VIP.
func TestAcceptMultipleHostsUniqueVIPs(t *testing.T) {
	reg := NewRegistry()

	hosts := []string{
		"api.github.com",
		"registry.npmjs.org",
		"pypi.org",
	}

	seen := make(map[string]string) // vip -> hostname

	for _, h := range hosts {
		vip, err := reg.Allocate(h)
		if err != nil {
			t.Fatalf("Allocate(%q): %v", h, err)
		}
		mustBeVIP4(t, vip)

		key := vip.String()
		if prev, dup := seen[key]; dup {
			t.Fatalf("VIP collision: %s and %s both got VIP %s", prev, h, key)
		}
		seen[key] = h
		t.Logf("%s -> %s", h, vip)
	}

	if len(seen) != len(hosts) {
		t.Fatalf("expected %d unique VIPs, got %d", len(hosts), len(seen))
	}
}

// TestAcceptGatewayLookup verifies that the gateway can resolve a VIP back to
// the original hostname, which is how it routes non-SNI traffic.
func TestAcceptGatewayLookup(t *testing.T) {
	reg := NewRegistry()

	const hostname = "postgres.internal"
	vip, err := reg.Allocate(hostname)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	// Gateway receives a TCP connection on vip and needs to know where to send
	// it.
	got, ok := reg.Lookup(vip)
	if !ok {
		t.Fatalf("Lookup(%s) returned ok=false", vip)
	}
	if got != hostname {
		t.Fatalf("Lookup(%s) = %q, want %q", vip, got, hostname)
	}
	t.Logf("gateway: VIP %s -> %s", vip, got)
}

// TestAcceptDualStack verifies that Allocate returns an IPv4 VIP and
// AllocateV6 returns an IPv6 VIP for the same hostname, and that both reverse-
// lookup to the same hostname.
func TestAcceptDualStack(t *testing.T) {
	reg := NewRegistry()

	const hostname = "api.github.com"

	v4, err := reg.Allocate(hostname)
	if err != nil {
		t.Fatalf("Allocate (v4): %v", err)
	}
	mustBeVIP4(t, v4)

	v6, err := reg.AllocateV6(hostname)
	if err != nil {
		t.Fatalf("AllocateV6 (v6): %v", err)
	}
	mustBeVIP6(t, v6)

	t.Logf("dual-stack: %s -> v4=%s v6=%s", hostname, v4, v6)

	// Both VIPs must map back to the same hostname.
	h4, ok4 := reg.Lookup(v4)
	if !ok4 {
		t.Fatalf("v4 Lookup(%s) returned ok=false", v4)
	}
	if h4 != hostname {
		t.Fatalf("v4 Lookup = %q, want %q", h4, hostname)
	}

	h6, ok6 := reg.Lookup(v6)
	if !ok6 {
		t.Fatalf("v6 Lookup(%s) returned ok=false", v6)
	}
	if h6 != hostname {
		t.Fatalf("v6 Lookup = %q, want %q", h6, hostname)
	}

	// The two VIPs must be in different address families.
	if v4.Equal(v6) {
		t.Fatal("v4 and v6 VIPs must differ")
	}
}

// TestAcceptSessionCleanup verifies that after Free() the hostname is gone from
// the registry and its former VIP is recycled on the next allocation.
func TestAcceptSessionCleanup(t *testing.T) {
	reg := NewRegistry()

	const hostname = "redis.session"
	vip, err := reg.Allocate(hostname)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	savedVIP := vip.String()

	// Sanity check: hostname is present before cleanup.
	if _, ok := reg.Lookup(vip); !ok {
		t.Fatal("pre-Free: Lookup returned ok=false")
	}

	// Session ends; cleanup the VIP.
	reg.Free(hostname)

	// Hostname must no longer be resolvable.
	if h, ok := reg.Lookup(net.ParseIP(savedVIP)); ok {
		t.Fatalf("post-Free: Lookup(%s) still returns %q", savedVIP, h)
	}

	// VIP must be recycled: the next allocation gets it back.
	vip2, err := reg.Allocate("new-tenant.internal")
	if err != nil {
		t.Fatalf("Allocate after Free: %v", err)
	}
	if vip2.String() != savedVIP {
		t.Fatalf("freed VIP not recycled: freed=%s new=%s", savedVIP, vip2)
	}

	// The recycled VIP must now map to the new hostname.
	h, ok := reg.Lookup(vip2)
	if !ok || h != "new-tenant.internal" {
		t.Fatalf("recycled VIP lookup: got %q ok=%v, want new-tenant.internal", h, ok)
	}
}

// TestAcceptDNSEndToEnd starts a real DNS server, sends an A query for
// "postgres.internal." and an AAAA query for the same name, and verifies that:
//   - the A record contains a VIP in 10.78.0.0/16
//   - the AAAA record contains a VIP in fd78::/16
//   - both reverse-lookup to "postgres.internal" in the registry
func TestAcceptDNSEndToEnd(t *testing.T) {
	reg := NewRegistry()
	addr, cancel := acceptStartServer(t, reg)
	defer cancel()

	c := dns.NewClient()
	const fqdn = "postgres.internal."

	// --- A query ---
	mA := dns.NewMsg(fqdn, dns.TypeA)
	rA, _, err := c.Exchange(context.Background(), mA, "udp", addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if rA.Rcode != dns.RcodeSuccess {
		t.Fatalf("A query rcode = %d, want %d (Success)", rA.Rcode, dns.RcodeSuccess)
	}
	if len(rA.Answer) != 1 {
		t.Fatalf("A query: got %d answers, want 1", len(rA.Answer))
	}
	aRec, ok := rA.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("A answer is %T, want *dns.A", rA.Answer[0])
	}
	v4IP := net.ParseIP(aRec.A.Addr.String())
	mustBeVIP4(t, v4IP)
	t.Logf("A: postgres.internal -> %s", v4IP)

	// Gateway reverse-lookup via A VIP.
	h4, ok4 := reg.Lookup(v4IP)
	if !ok4 {
		t.Fatalf("registry Lookup(%s) ok=false after DNS A query", v4IP)
	}
	if h4 != "postgres.internal" {
		t.Fatalf("registry Lookup(%s) = %q, want postgres.internal", v4IP, h4)
	}

	// --- AAAA query ---
	mAAAA := dns.NewMsg(fqdn, dns.TypeAAAA)
	rAAAA, _, err := c.Exchange(context.Background(), mAAAA, "udp", addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if rAAAA.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA query rcode = %d, want %d (Success)", rAAAA.Rcode, dns.RcodeSuccess)
	}
	if len(rAAAA.Answer) != 1 {
		t.Fatalf("AAAA query: got %d answers, want 1", len(rAAAA.Answer))
	}
	aaaaRec, ok := rAAAA.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("AAAA answer is %T, want *dns.AAAA", rAAAA.Answer[0])
	}
	v6IP := net.ParseIP(aaaaRec.AAAA.Addr.String())
	mustBeVIP6(t, v6IP)
	t.Logf("AAAA: postgres.internal -> %s", v6IP)

	// Gateway reverse-lookup via AAAA VIP.
	h6, ok6 := reg.Lookup(v6IP)
	if !ok6 {
		t.Fatalf("registry Lookup(%s) ok=false after DNS AAAA query", v6IP)
	}
	if h6 != "postgres.internal" {
		t.Fatalf("registry Lookup(%s) = %q, want postgres.internal", v6IP, h6)
	}
}

// TestAcceptStatsTracking verifies that Stats() reports the correct allocated
// and available counts after inserting five distinct hostnames.
func TestAcceptStatsTracking(t *testing.T) {
	reg := NewRegistry()

	hosts := []string{
		"api.github.com",
		"registry.npmjs.org",
		"pypi.org",
		"hub.docker.com",
		"packages.debian.org",
	}

	for _, h := range hosts {
		if _, err := reg.Allocate(h); err != nil {
			t.Fatalf("Allocate(%q): %v", h, err)
		}
	}

	const wantAllocated = 5
	const wantAvailable = ipv4PoolSize - wantAllocated // 65534 - 5 = 65529

	allocated, available := reg.Stats()
	if allocated != wantAllocated {
		t.Errorf("Stats allocated = %d, want %d", allocated, wantAllocated)
	}
	if available != wantAvailable {
		t.Errorf("Stats available = %d, want %d", available, wantAvailable)
	}
	t.Logf("Stats: allocated=%d available=%d", allocated, available)
}

// TestAccept is the single entry-point discovered by -run Accept. It fans out
// into independent sub-tests, each with its own registry.
func TestAccept(t *testing.T) {
	t.Run("FirstResolution", TestAcceptFirstResolution)
	t.Run("StickyVIP", TestAcceptStickyVIP)
	t.Run("MultipleHostsUniqueVIPs", TestAcceptMultipleHostsUniqueVIPs)
	t.Run("GatewayLookup", TestAcceptGatewayLookup)
	t.Run("DualStack", TestAcceptDualStack)
	t.Run("SessionCleanup", TestAcceptSessionCleanup)
	t.Run("DNSEndToEnd", TestAcceptDNSEndToEnd)
	t.Run("StatsTracking", TestAcceptStatsTracking)
}
