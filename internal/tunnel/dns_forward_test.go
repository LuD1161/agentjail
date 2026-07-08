package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

// encodeUDP4 builds an IPv4 + UDP datagram carrying payload, with exact
// checksums. A wrong checksum is silently dropped by the stack. It mirrors
// forwarder_test.go's encodeTCP4.
func encodeUDP4(src, dst netip.AddrPort, payload []byte) []byte {
	srcAddr := tcpip.AddrFromSlice(src.Addr().AsSlice())
	dstAddr := tcpip.AddrFromSlice(dst.Addr().AsSlice())

	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.IPv4MinimumSize + udpLen
	pkt := make([]byte, totalLen)

	ip := header.IPv4(pkt[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		ID:          1,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udpHdr := header.UDP(pkt[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(udpLen),
	})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	xsum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber, srcAddr, dstAddr, uint16(udpLen),
	)
	xsum = checksum.Checksum(payload, xsum)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))
	return pkt
}

// packDNSQuery builds a DNS A-record query for name in wire format.
func packDNSQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := dns.NewMsg(name, qtype)
	if err := m.Pack(); err != nil {
		t.Fatalf("packing DNS query: %v", err)
	}
	return m.Data
}

// TestForwarderResolvesDNSFromRegistry is the AGE-148/W1 regression test: an
// inbound UDP:53 A-record query for example.com. injected from the agent side
// must be answered from the VIP registry — with an A record in the VIP range —
// and the returned VIP must be resolvable back to "example.com" via the
// registry. This proves DNS reaches the registry end-to-end through the
// transparent forwarder, so VIPs are allocated and name resolution works.
func TestForwarderResolvesDNSFromRegistry(t *testing.T) {
	reg := dnsvip.NewRegistry()
	resolve := func(q []byte) ([]byte, error) { return dnsvip.Resolve(reg, q) }

	fs, err := newForwardStack(1420, func(net.Conn) {
		t.Error("DNS traffic must not produce an accepted TCP connection")
	}, resolve)
	if err != nil {
		t.Fatalf("newForwardStack: %v", err)
	}
	defer fs.Close()

	// Any resolver IP:53 the agent addresses; deliberately not the stack's own
	// address (the stack has none), exercising the promiscuous/spoofing path.
	resolver := netip.MustParseAddrPort("10.78.0.1:53")
	agent := netip.MustParseAddrPort("10.78.0.2:34567")

	query := packDNSQuery(t, "example.com.", dns.TypeA)
	fs.InjectInbound(encodeUDP4(agent, resolver, query))

	readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out := fs.ReadOutbound(readCtx)
	if out == nil {
		t.Fatal("forwarder emitted no DNS response: UDP:53 query was dropped (W1 not fixed)")
	}

	ip := header.IPv4(out)
	if !ip.IsValid(len(out)) {
		t.Fatalf("outbound packet is not valid IPv4 (len=%d)", len(out))
	}
	if got := ip.DestinationAddress().String(); got != agent.Addr().String() {
		t.Fatalf("DNS response dst = %q, want agent %q", got, agent.Addr())
	}
	if ip.TransportProtocol() != header.UDPProtocolNumber {
		t.Fatalf("outbound protocol = %d, want UDP", ip.TransportProtocol())
	}
	udpHdr := header.UDP(out[ip.HeaderLength():])
	if got := udpHdr.SourcePort(); got != 53 {
		t.Fatalf("DNS response src port = %d, want 53", got)
	}
	payload := out[int(ip.HeaderLength())+header.UDPMinimumSize:]

	resp := new(dns.Msg)
	resp.Data = payload
	if err := resp.Unpack(); err != nil {
		t.Fatalf("unpacking DNS response: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	vipStr := a.A.Addr.String()

	// The answer must be in the registry's IPv4 VIP range (10.78.0.0/16).
	vipRange := netip.MustParsePrefix("10.78.0.0/16")
	if !vipRange.Contains(a.A.Addr) {
		t.Fatalf("answer IP %s is not in the VIP range %s", vipStr, vipRange)
	}

	// ...and that VIP must map back to the queried hostname in the registry.
	host, found := reg.Lookup(net.ParseIP(vipStr))
	if !found {
		t.Fatalf("registry has no mapping for allocated VIP %s", vipStr)
	}
	if host != "example.com" {
		t.Fatalf("registry.Lookup(%s) = %q, want %q", vipStr, host, "example.com")
	}
}

// TestForwarderDropsNonDNSUDP asserts a UDP datagram to a non-53 port produces
// no outbound response (it is dropped, not answered or relayed).
func TestForwarderDropsNonDNSUDP(t *testing.T) {
	reg := dnsvip.NewRegistry()
	resolve := func(q []byte) ([]byte, error) { return dnsvip.Resolve(reg, q) }

	fs, err := newForwardStack(1420, func(net.Conn) {
		t.Error("UDP traffic must not produce an accepted TCP connection")
	}, resolve)
	if err != nil {
		t.Fatalf("newForwardStack: %v", err)
	}
	defer fs.Close()

	dst := netip.MustParseAddrPort("10.78.0.1:9999") // non-DNS UDP port
	agent := netip.MustParseAddrPort("10.78.0.2:40000")

	// A well-formed DNS query, but sent to the wrong port: must be dropped.
	query := packDNSQuery(t, "example.com.", dns.TypeA)
	fs.InjectInbound(encodeUDP4(agent, dst, query))

	readCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if out := fs.ReadOutbound(readCtx); out != nil {
		t.Fatalf("non-DNS UDP produced an outbound response of %d bytes; want none", len(out))
	}
}
