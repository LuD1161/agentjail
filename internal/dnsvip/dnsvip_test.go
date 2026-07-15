package dnsvip

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestAllocate(t *testing.T) {
	r := NewRegistry()
	ip1, err := r.Allocate("host-a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip1.String(); got != "10.78.0.1" {
		t.Fatalf("first alloc = %s, want 10.78.0.1", got)
	}

	ip2, err := r.Allocate("host-b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip2.String(); got != "10.78.0.2" {
		t.Fatalf("second alloc = %s, want 10.78.0.2", got)
	}
}

func TestAllocateSameHost(t *testing.T) {
	r := NewRegistry()
	ip1, err := r.Allocate("db.internal")
	if err != nil {
		t.Fatal(err)
	}
	ip2, err := r.Allocate("db.internal")
	if err != nil {
		t.Fatal(err)
	}
	if !ip1.Equal(ip2) {
		t.Fatalf("same host returned different VIPs: %s vs %s", ip1, ip2)
	}
}

func TestLookup(t *testing.T) {
	r := NewRegistry()
	vip, err := r.Allocate("redis.prod")
	if err != nil {
		t.Fatal(err)
	}
	host, ok := r.Lookup(vip)
	if !ok {
		t.Fatal("lookup returned ok=false")
	}
	if host != "redis.prod" {
		t.Fatalf("lookup = %q, want %q", host, "redis.prod")
	}
}

func TestLookupMiss(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Lookup(net.ParseIP("10.78.99.99"))
	if ok {
		t.Fatal("expected ok=false for unknown VIP")
	}
}

func TestFree(t *testing.T) {
	r := NewRegistry()

	_, err := r.Allocate("a.test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Allocate("b.test")
	if err != nil {
		t.Fatal(err)
	}

	r.Free("a.test")

	ip, err := r.Allocate("c.test")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "10.78.0.1" {
		t.Fatalf("after free, alloc = %s, want 10.78.0.1 (recycled)", got)
	}

	host, ok := r.Lookup(ip)
	if !ok || host != "c.test" {
		t.Fatalf("reverse lookup after recycle: host=%q ok=%v", host, ok)
	}

	host, _ = r.Lookup(net.ParseIP("10.78.0.1"))
	if host == "a.test" {
		t.Fatal("freed hostname should not be in reverse map")
	}
}

func TestConcurrent(t *testing.T) {
	r := NewRegistry()
	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("host-%d.test", i)
			ip, err := r.Allocate(host)
			if err != nil {
				errs <- fmt.Errorf("alloc %s: %w", host, err)
				return
			}
			got, ok := r.Lookup(ip)
			if !ok || got != host {
				errs <- fmt.Errorf("lookup %s: got %q ok=%v", host, got, ok)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	alloc, avail := r.Stats()
	if alloc != n {
		t.Fatalf("allocated = %d, want %d", alloc, n)
	}
	if avail != ipv4PoolSize-n {
		t.Fatalf("available = %d, want %d", avail, ipv4PoolSize-n)
	}
}

func TestExhaustion(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustion test allocates 65534 entries")
	}

	r := NewRegistry()
	for i := range ipv4PoolSize {
		_, err := r.Allocate(fmt.Sprintf("h%d.test", i))
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i+1, err)
		}
	}

	alloc, avail := r.Stats()
	if alloc != ipv4PoolSize {
		t.Fatalf("allocated = %d, want %d", alloc, ipv4PoolSize)
	}
	if avail != 0 {
		t.Fatalf("available = %d, want 0", avail)
	}

	_, err := r.Allocate("one-too-many.test")
	if err != ErrPoolExhausted {
		t.Fatalf("expected ErrPoolExhausted, got %v", err)
	}
}

func startTestServer(t *testing.T, reg *Registry) (addr string, cancel context.CancelFunc) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(pc.LocalAddr().String(), reg)
	srv.PacketConn(pc)

	ctx, cancelFn := context.WithCancel(context.Background())
	go srv.ListenAndServe(ctx)
	time.Sleep(10 * time.Millisecond)

	return pc.LocalAddr().String(), cancelFn
}

func TestDNSRoundTrip(t *testing.T) {
	reg := NewRegistry()
	addr, cancel := startTestServer(t, reg)
	defer cancel()

	c := dns.NewClient()
	m := dns.NewMsg("db.prod.internal.", dns.TypeA)
	m.ID = 0xABCD

	r, _, err := c.Exchange(context.Background(), m, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	if r.ID != 0xABCD {
		t.Fatalf("response ID = %x, want 0xABCD", r.ID)
	}
	if !r.Response {
		t.Fatal("expected response bit set")
	}
	if len(r.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(r.Answer))
	}

	a, ok := r.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", r.Answer[0])
	}
	gotIP := a.A.Addr.String()
	if gotIP != "10.78.0.1" {
		t.Fatalf("DNS response IP = %s, want 10.78.0.1", gotIP)
	}

	host, found := reg.Lookup(net.ParseIP(gotIP))
	if !found || host != "db.prod.internal" {
		t.Fatalf("registry lookup: host=%q found=%v", host, found)
	}
}

// TestDNSAAAA verifies AAAA queries return NODATA (NOERROR with no answer
// records) rather than an IPv6 VIP. The transparent forward stack only routes
// IPv4 VIPs, so advertising an AAAA VIP would make v6-preferring clients dial
// an unroutable address and hang; NODATA makes them fall back to the A record.
func TestDNSAAAA(t *testing.T) {
	reg := NewRegistry()
	addr, cancel := startTestServer(t, reg)
	defer cancel()

	c := dns.NewClient()
	m := dns.NewMsg("mongo.internal.", dns.TypeAAAA)
	m.ID = 0x1234

	r, _, err := c.Exchange(context.Background(), m, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA rcode = %d, want %d (NODATA is NOERROR)", r.Rcode, dns.RcodeSuccess)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("got %d answers, want 0 (NODATA)", len(r.Answer))
	}
}
