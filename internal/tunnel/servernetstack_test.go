package tunnel

// servernetstack_test.go — T0.1/T0.3 coverage: the promiscuous serverNetstack
// accepts a connection to an arbitrary destination, and dnsPacketConn is a
// usable net.PacketConn bound inside the stack. See servernetstack.go.

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestServerNetstack_AcceptsArbitraryDestinationSYN mirrors
// TestForwarderAcceptsArbitraryDestinationSYN (forwarder_test.go): a SYN to a
// destination that is NOT the stack's own gwAddr must still be accepted,
// proving promiscuous mode + spoofing are effective — the same property the
// macOS NE loopback path needs from a wgtun.Device.
func TestServerNetstack_AcceptsArbitraryDestinationSYN(t *testing.T) {
	gwAddr := netip.MustParseAddr("10.78.0.1")
	ns, err := newServerNetstack(gwAddr, netip.Addr{}, 1420)
	if err != nil {
		t.Fatalf("newServerNetstack: %v", err)
	}
	defer ns.Close()

	accepted := make(chan net.Conn, 1)
	ns.serveTCP(func(c net.Conn) { accepted <- c })

	// Arbitrary VIP the agent "dialed" — not gwAddr, not any address the
	// stack owns.
	vip := netip.MustParseAddrPort("10.78.5.5:443")
	agent := netip.MustParseAddrPort("10.78.0.2:12345")

	const clientISN = 0x1000
	if _, err := ns.Write([][]byte{encodeTCP4(agent, vip, clientISN, 0, header.TCPFlagSyn)}, 0); err != nil {
		t.Fatalf("Write SYN: %v", err)
	}

	// Read the SYN-ACK the stack emits back, to complete the handshake.
	bufs := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	readDone := make(chan struct{})
	var synack []byte
	go func() {
		n, err := ns.Read(bufs, sizes, 0)
		if err == nil && n > 0 {
			synack = append([]byte(nil), bufs[0][:sizes[0]]...)
		}
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("serverNetstack emitted no SYN-ACK: arbitrary-destination SYN was dropped")
	}
	if synack == nil {
		t.Fatal("serverNetstack emitted no SYN-ACK: arbitrary-destination SYN was dropped")
	}

	ip := header.IPv4(synack)
	if !ip.IsValid(len(synack)) {
		t.Fatalf("outbound packet is not valid IPv4 (len=%d)", len(synack))
	}
	if got := ip.DestinationAddress().String(); got != agent.Addr().String() {
		t.Fatalf("SYN-ACK dst = %q, want agent %q", got, agent.Addr())
	}
	tcpReply := header.TCP(synack[ip.HeaderLength():])
	if !tcpReply.Flags().Contains(header.TCPFlagSyn | header.TCPFlagAck) {
		t.Fatalf("expected SYN-ACK, got flags %v", tcpReply.Flags())
	}
	serverISN := tcpReply.SequenceNumber()

	// Complete the handshake: ACK with seq=clientISN+1, ack=serverISN+1.
	if _, err := ns.Write([][]byte{encodeTCP4(agent, vip, clientISN+1, serverISN+1, header.TCPFlagAck)}, 0); err != nil {
		t.Fatalf("Write ACK: %v", err)
	}

	select {
	case c := <-accepted:
		defer c.Close()
		got := c.LocalAddr().String()
		want := "10.78.5.5:443"
		if got != want {
			t.Fatalf("accepted conn LocalAddr = %q, want %q (original destination VIP)", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serverNetstack never delivered the accepted conn after handshake")
	}
}

// TestServerNetstack_DNSPacketConn asserts dnsPacketConn returns a usable
// net.PacketConn bound to gwAddr:53 inside the stack: a datagram sent to that
// address (from inside the stack) is readable off the conn.
func TestServerNetstack_DNSPacketConn(t *testing.T) {
	gwAddr := netip.MustParseAddr("10.78.0.1")
	ns, err := newServerNetstack(gwAddr, netip.Addr{}, 1420)
	if err != nil {
		t.Fatalf("newServerNetstack: %v", err)
	}
	defer ns.Close()

	pc, err := ns.dnsPacketConn(gwAddr, 53)
	if err != nil {
		t.Fatalf("dnsPacketConn: %v", err)
	}
	defer pc.Close()

	if pc.LocalAddr() == nil {
		t.Fatal("dnsPacketConn: LocalAddr is nil")
	}

	// Send a UDP datagram from outside the stack (agent side) to gwAddr:53
	// and confirm the packet conn reads it — proof the conn is a live,
	// usable net.PacketConn rather than an inert placeholder.
	src := netip.MustParseAddrPort("10.78.0.2:40000")
	dst := netip.AddrPortFrom(gwAddr, 53)
	payload := []byte("dns-query")
	if _, err := ns.Write([][]byte{encodeUDP4(src, dst, payload)}, 0); err != nil {
		t.Fatalf("Write UDP: %v", err)
	}

	readDone := make(chan struct{})
	buf := make([]byte, 512)
	var n int
	var readErr error
	go func() {
		n, _, readErr = pc.ReadFrom(buf)
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("dnsPacketConn never received the injected datagram")
	}
	if readErr != nil {
		t.Fatalf("ReadFrom: %v", readErr)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("ReadFrom payload = %q, want %q", buf[:n], payload)
	}
}
