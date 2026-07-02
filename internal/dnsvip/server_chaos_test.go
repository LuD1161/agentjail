package dnsvip

import (
	"context"
	"crypto/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// chaosServer starts a test DNS server and returns its address and a cancel function.
func chaosServer(t *testing.T) (addr string, cancel context.CancelFunc) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	srv := NewServer(pc.LocalAddr().String(), reg)
	srv.PacketConn(pc)

	ctx, cancelFn := context.WithCancel(context.Background())
	go srv.ListenAndServe(ctx)
	// Give the server a moment to start.
	time.Sleep(20 * time.Millisecond)

	return pc.LocalAddr().String(), cancelFn
}

// sendRawUDP dials a UDP socket, sends raw bytes, waits briefly for a response
// (ignoring it), then closes. Returns any dial/write error.
func sendRawUDP(addr string, data []byte) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return err
	}

	// Try to read a response with a short deadline; it's OK if there is none.
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)
	return nil
}

// ChaosTest1_GarbageBytes sends 512 random bytes to the server and verifies
// it stays alive by successfully answering a normal query afterwards.
func TestChaos1_GarbageBytes(t *testing.T) {
	addr, cancel := chaosServer(t)
	defer cancel()

	garbage := make([]byte, 512)
	_, _ = rand.Read(garbage)

	if err := sendRawUDP(addr, garbage); err != nil {
		t.Fatalf("sendRawUDP error: %v", err)
	}

	// Server must still respond to a valid query.
	c := dns.NewClient()
	m := dns.NewMsg("alive.check.", dns.TypeA)
	r, _, err := c.Exchange(context.Background(), m, "udp", addr)
	if err != nil {
		t.Fatalf("server did not respond after garbage bytes: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 answer after garbage, got %d", len(r.Answer))
	}
}

// ChaosTest2_TruncatedDNSPacket sends a valid 12-byte DNS header followed by
// an incomplete question section and verifies the server survives.
func TestChaos2_TruncatedDNSPacket(t *testing.T) {
	addr, cancel := chaosServer(t)
	defer cancel()

	// Build a real query and then truncate it mid-question.
	m := dns.NewMsg("example.com.", dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	full := m.Data

	// Test several truncation lengths.
	for _, cut := range []int{0, 1, 6, 12, 13, len(full)/2, len(full) - 1} {
		if cut > len(full) {
			cut = len(full) - 1
		}
		pkt := full[:cut]
		if err := sendRawUDP(addr, pkt); err != nil {
			t.Fatalf("sendRawUDP (cut=%d) error: %v", cut, err)
		}
	}

	// Server must still answer valid queries.
	c := dns.NewClient()
	m2 := dns.NewMsg("still.alive.", dns.TypeA)
	if _, _, err := c.Exchange(context.Background(), m2, "udp", addr); err != nil {
		t.Fatalf("server unresponsive after truncated packets: %v", err)
	}
}

// ChaosTest3_OversizedPackets sends DNS packets that exceed 512 and 4096 bytes.
func TestChaos3_OversizedPackets(t *testing.T) {
	addr, cancel := chaosServer(t)
	defer cancel()

	for _, size := range []int{513, 1024, 4097, 65507} {
		pkt := make([]byte, size)
		// Set a plausible DNS header: QR=0, QDCOUNT=1, but the body is garbage.
		// Header: ID (2), flags (2), qdcount=1 (2), ancount (2), nscount (2), arcount (2)
		pkt[0] = 0xDE
		pkt[1] = 0xAD
		pkt[2] = 0x01
		pkt[3] = 0x00
		pkt[4] = 0x00
		pkt[5] = 0x01 // qdcount = 1
		_, _ = rand.Read(pkt[12:])

		if err := sendRawUDP(addr, pkt); err != nil {
			t.Fatalf("sendRawUDP (size=%d) error: %v", size, err)
		}
	}

	c := dns.NewClient()
	m := dns.NewMsg("oversized.test.", dns.TypeA)
	if _, _, err := c.Exchange(context.Background(), m, "udp", addr); err != nil {
		t.Fatalf("server unresponsive after oversized packets: %v", err)
	}
}

// ChaosTest4_RapidFire sends 100 concurrent queries and checks for goroutine leaks.
func TestChaos4_RapidFire(t *testing.T) {
	addr, cancel := chaosServer(t)
	defer cancel()

	goroutinesBefore := runtime.NumGoroutine()

	const n = 100
	var wg sync.WaitGroup
	errors := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := dns.NewClient()
			// Assign unique IDs per query.
			m := dns.NewMsg("rapid.fire.test.", dns.TypeA)
			m.ID = uint16(i + 1)
			_, _, err := c.Exchange(context.Background(), m, "udp", addr)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("rapid-fire query error: %v", err)
	}

	// Give lingering goroutines a moment to exit.
	time.Sleep(100 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()

	// Allow a generous delta (10 goroutines) to account for runtime noise.
	if goroutinesAfter > goroutinesBefore+10 {
		t.Errorf("possible goroutine leak: before=%d after=%d (delta=%d)",
			goroutinesBefore, goroutinesAfter, goroutinesAfter-goroutinesBefore)
	}
}

// ChaosTest5_UnknownRecordType sends queries for TypeNS, TypeMX, TypeSRV and
// expects RcodeRefused from the server.
func TestChaos5_UnknownRecordType(t *testing.T) {
	addr, cancel := chaosServer(t)
	defer cancel()

	c := dns.NewClient()

	for _, qtype := range []uint16{dns.TypeNS, dns.TypeMX, dns.TypeSRV, dns.TypeTXT, dns.TypeCNAME} {
		m := dns.NewMsg("example.com.", qtype)
		r, _, err := c.Exchange(context.Background(), m, "udp", addr)
		if err != nil {
			t.Errorf("qtype=%d: exchange error: %v", qtype, err)
			continue
		}
		if r.Rcode != dns.RcodeRefused {
			t.Errorf("qtype=%d: want RcodeRefused (%d), got %d", qtype, dns.RcodeRefused, r.Rcode)
		}
	}
}

// ChaosTest6_ClientClosesEarly sends a query then immediately closes the client
// connection before reading the response. The server must survive.
func TestChaos6_ClientClosesEarly(t *testing.T) {
	addr, cancel := chaosServer(t)
	defer cancel()

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	for range 10 {
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatalf("DialUDP: %v", err)
		}

		// Build and pack a valid DNS query.
		m := dns.NewMsg("close.me.early.", dns.TypeA)
		if err := m.Pack(); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		_, err = conn.Write(m.Data)
		if err != nil {
			conn.Close()
			t.Fatalf("Write: %v", err)
		}

		// Close immediately without reading the response.
		conn.Close()
	}

	// Brief pause so the server can process any in-flight responses.
	time.Sleep(50 * time.Millisecond)

	// Server must still be healthy.
	c := dns.NewClient()
	m := dns.NewMsg("server.alive.", dns.TypeA)
	if _, _, err := c.Exchange(context.Background(), m, "udp", addr); err != nil {
		t.Fatalf("server not responding after early-close clients: %v", err)
	}
}

// ChaosTest7_ContextCancelShutdown starts a server, cancels its context, and
// verifies it shuts down cleanly without goroutine leaks.
func TestChaos7_ContextCancelShutdown(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	srv := NewServer(pc.LocalAddr().String(), reg)
	srv.PacketConn(pc)

	ctx, cancel := context.WithCancel(context.Background())

	goroutinesBefore := runtime.NumGoroutine()

	done := make(chan error, 1)
	go func() {
		done <- srv.ListenAndServe(ctx)
	}()

	// Wait for server to start.
	time.Sleep(20 * time.Millisecond)

	// Cancel the context to trigger shutdown.
	cancel()

	select {
	case <-done:
		// Server exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down within 2s after context cancel")
	}

	// Give goroutines time to exit.
	time.Sleep(100 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()

	if goroutinesAfter > goroutinesBefore+5 {
		t.Errorf("goroutine leak after shutdown: before=%d after=%d",
			goroutinesBefore, goroutinesAfter)
	}
}

// ChaosTest8_AandAAAAReturnSameRegistry verifies that A and AAAA queries for
// the same hostname are backed by the same registry entry (same allocation
// slot) and that a reverse lookup on each VIP resolves to the same hostname.
func TestChaos8_AandAAAASameRegistry(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	srv := NewServer(pc.LocalAddr().String(), reg)
	srv.PacketConn(pc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ListenAndServe(ctx)
	time.Sleep(20 * time.Millisecond)

	addr := pc.LocalAddr().String()
	c := dns.NewClient()

	const host = "shared.host.internal."

	// Query A.
	mA := dns.NewMsg(host, dns.TypeA)
	rA, _, err := c.Exchange(context.Background(), mA, "udp", addr)
	if err != nil {
		t.Fatalf("A query error: %v", err)
	}
	if len(rA.Answer) != 1 {
		t.Fatalf("A: want 1 answer, got %d", len(rA.Answer))
	}
	aRec, ok := rA.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("A answer is %T, want *dns.A", rA.Answer[0])
	}
	ipv4 := aRec.A.Addr.String()

	// Query AAAA.
	mAAAA := dns.NewMsg(host, dns.TypeAAAA)
	rAAAA, _, err := c.Exchange(context.Background(), mAAAA, "udp", addr)
	if err != nil {
		t.Fatalf("AAAA query error: %v", err)
	}
	if len(rAAAA.Answer) != 1 {
		t.Fatalf("AAAA: want 1 answer, got %d", len(rAAAA.Answer))
	}
	aaaaRec, ok := rAAAA.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("AAAA answer is %T, want *dns.AAAA", rAAAA.Answer[0])
	}
	ipv6 := aaaaRec.AAAA.Addr.String()

	t.Logf("host=%s A=%s AAAA=%s", host, ipv4, ipv6)

	// Both VIPs must resolve back to the same hostname in the registry.
	hostFromV4, okV4 := reg.Lookup(net.ParseIP(ipv4))
	hostFromV6, okV6 := reg.Lookup(net.ParseIP(ipv6))

	if !okV4 {
		t.Errorf("registry lookup for A VIP %s failed", ipv4)
	}
	if !okV6 {
		t.Errorf("registry lookup for AAAA VIP %s failed", ipv6)
	}

	wantHost := "shared.host.internal" // fqdnToHostname strips trailing dot
	if hostFromV4 != wantHost {
		t.Errorf("A reverse lookup: got %q, want %q", hostFromV4, wantHost)
	}
	if hostFromV6 != wantHost {
		t.Errorf("AAAA reverse lookup: got %q, want %q", hostFromV6, wantHost)
	}

	// Both VIPs must point to the same hostname (consistency).
	if hostFromV4 != hostFromV6 {
		t.Errorf("A and AAAA registry entries point to different hostnames: %q vs %q",
			hostFromV4, hostFromV6)
	}

	// A second A query must return the SAME VIP (idempotent allocation).
	rA2, _, err := c.Exchange(context.Background(), dns.NewMsg(host, dns.TypeA), "udp", addr)
	if err != nil {
		t.Fatalf("second A query error: %v", err)
	}
	aRec2, ok := rA2.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("second A answer is %T", rA2.Answer[0])
	}
	if ipv4b := aRec2.A.Addr.String(); ipv4b != ipv4 {
		t.Errorf("second A query returned different VIP: first=%s second=%s", ipv4, ipv4b)
	}

	// Verify A and AAAA VIPs are actually different address families.
	parsedV4 := net.ParseIP(ipv4)
	parsedV6 := net.ParseIP(ipv6)

	if parsedV4.To4() == nil {
		t.Errorf("A response %s is not an IPv4 address", ipv4)
	}
	if parsedV6.To4() != nil {
		t.Errorf("AAAA response %s looks like an IPv4 address", ipv6)
	}
}
