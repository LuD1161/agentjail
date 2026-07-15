package dnsvip

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestE2E_DNSVIPWorkflow(t *testing.T) {
	reg := NewRegistry()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(pc.LocalAddr().String(), reg)
	srv.PacketConn(pc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	addr := pc.LocalAddr().String()
	c := dns.NewClient()

	// Scenario 1: First resolution — agent queries api.github.com
	t.Run("first_resolution", func(t *testing.T) {
		m := dns.NewMsg("api.github.com.", dns.TypeA)
		r, _, err := c.Exchange(context.Background(), m, "udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(r.Answer))
		}
		a := r.Answer[0].(*dns.A)
		ip := a.A.Addr.String()
		if ip != "10.78.0.1" {
			t.Fatalf("first VIP = %s, want 10.78.0.1", ip)
		}
		t.Logf("api.github.com -> %s ✓", ip)
	})

	// Scenario 2: Same host again — sticky VIP
	t.Run("sticky_vip", func(t *testing.T) {
		m := dns.NewMsg("api.github.com.", dns.TypeA)
		r, _, _ := c.Exchange(context.Background(), m, "udp", addr)
		a := r.Answer[0].(*dns.A)
		if a.A.Addr.String() != "10.78.0.1" {
			t.Fatalf("same host returned different VIP: %s", a.A.Addr)
		}
		t.Logf("api.github.com -> %s (sticky) ✓", a.A.Addr)
	})

	// Scenario 3: Different host — new VIP
	t.Run("different_host", func(t *testing.T) {
		m := dns.NewMsg("registry.npmjs.org.", dns.TypeA)
		r, _, _ := c.Exchange(context.Background(), m, "udp", addr)
		a := r.Answer[0].(*dns.A)
		if a.A.Addr.String() == "10.78.0.1" {
			t.Fatal("different host got same VIP as first")
		}
		t.Logf("registry.npmjs.org -> %s ✓", a.A.Addr)
	})

	// Scenario 4: AAAA query returns NODATA (IPv4-only forward stack), so
	// v6-preferring clients fall back to the A record instead of dialing an
	// unroutable v6 VIP.
	t.Run("aaaa_query", func(t *testing.T) {
		m := dns.NewMsg("db.internal.", dns.TypeAAAA)
		r, _, _ := c.Exchange(context.Background(), m, "udp", addr)
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("AAAA rcode = %d, want %d (NODATA)", r.Rcode, dns.RcodeSuccess)
		}
		if len(r.Answer) != 0 {
			t.Fatalf("expected 0 AAAA answers (NODATA), got %d", len(r.Answer))
		}
		t.Logf("db.internal (AAAA) -> NODATA ✓")
	})

	// Scenario 5: Gateway reverse lookup — this is how the gateway maps VIP→hostname
	t.Run("gateway_reverse_lookup", func(t *testing.T) {
		vip := net.ParseIP("10.78.0.1")
		host, ok := reg.Lookup(vip)
		if !ok || host != "api.github.com" {
			t.Fatalf("reverse lookup failed: host=%q ok=%v", host, ok)
		}
		t.Logf("10.78.0.1 -> %s ✓", host)
	})

	// Scenario 6: Multiple hosts for realistic traffic
	t.Run("multi_host_traffic", func(t *testing.T) {
		hosts := []string{"pypi.org.", "crates.io.", "golang.org.", "hub.docker.com.", "ghcr.io."}
		for _, h := range hosts {
			m := dns.NewMsg(h, dns.TypeA)
			r, _, err := c.Exchange(context.Background(), m, "udp", addr)
			if err != nil {
				t.Fatalf("query %s failed: %v", h, err)
			}
			if len(r.Answer) != 1 {
				t.Fatalf("query %s: expected 1 answer, got %d", h, len(r.Answer))
			}
		}
		alloc, avail := reg.Stats()
		// 1 (github) + 1 (npm) + 5 new = 7. db.internal was only AAAA-queried,
		// which now returns NODATA without allocating a VIP.
		if alloc != 7 {
			t.Fatalf("expected 7 allocations, got %d", alloc)
		}
		t.Logf("7 hosts allocated, %d available ✓", avail)
	})

	// Scenario 7: Rapid concurrent queries (simulates agent spawning many connections)
	t.Run("concurrent_agent_queries", func(t *testing.T) {
		errs := make(chan error, 20)
		for i := range 20 {
			go func(i int) {
				m := dns.NewMsg(fmt.Sprintf("svc-%d.cluster.local.", i), dns.TypeA)
				r, _, err := c.Exchange(context.Background(), m, "udp", addr)
				if err != nil {
					errs <- err
					return
				}
				if len(r.Answer) != 1 {
					errs <- fmt.Errorf("svc-%d: expected 1 answer, got %d", i, len(r.Answer))
					return
				}
				errs <- nil
			}(i)
		}
		for range 20 {
			if err := <-errs; err != nil {
				t.Error(err)
			}
		}
		t.Logf("20 concurrent queries all resolved ✓")
	})

	// Scenario 8: Unknown query type — refused
	t.Run("unknown_query_type", func(t *testing.T) {
		m := dns.NewMsg("example.com.", dns.TypeMX)
		r, _, _ := c.Exchange(context.Background(), m, "udp", addr)
		if r.Rcode != dns.RcodeRefused {
			t.Fatalf("expected RcodeRefused for MX, got %d", r.Rcode)
		}
		t.Logf("MX query refused ✓")
	})

	// Scenario 9: Shutdown — context cancel stops server
	t.Run("clean_shutdown", func(t *testing.T) {
		cancel()
		time.Sleep(50 * time.Millisecond)
		m := dns.NewMsg("after-shutdown.test.", dns.TypeA)
		_, _, err := c.Exchange(context.Background(), m, "udp", addr)
		if err == nil {
			t.Fatal("expected error after shutdown")
		}
		t.Logf("server shut down cleanly ✓")
	})
}
