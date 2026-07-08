package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// encodeTCP4 builds an IPv4 + TCP segment (no payload) with exact checksums. A
// wrong checksum is silently dropped by the stack.
func encodeTCP4(src, dst netip.AddrPort, seq, ack uint32, flags header.TCPFlags) []byte {
	srcAddr := tcpip.AddrFromSlice(src.Addr().AsSlice())
	dstAddr := tcpip.AddrFromSlice(dst.Addr().AsSlice())

	totalLen := header.IPv4MinimumSize + header.TCPMinimumSize
	pkt := make([]byte, totalLen)

	ip := header.IPv4(pkt[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		ID:          1,
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	tcpHdr := header.TCP(pkt[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, srcAddr, dstAddr, uint16(header.TCPMinimumSize),
	)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))
	return pkt
}

// TestForwarderAcceptsArbitraryDestinationSYN is the S-F1 regression test: a
// SYN to an arbitrary VIP that is NOT the stack's own address must be accepted,
// and the accepted conn's LocalAddr() must be that original destination.
//
// tcp.ForwarderRequest.CreateEndpoint performs the full 3-way handshake, so the
// test drives a real handshake: inject the SYN, read the SYN-ACK the stack
// emits, then inject the completing ACK — only then does the endpoint (and the
// accept callback) come alive.
func TestForwarderAcceptsArbitraryDestinationSYN(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	fs, err := newForwardStack(1420, func(c net.Conn) {
		accepted <- c
	}, nil)
	if err != nil {
		t.Fatalf("newForwardStack: %v", err)
	}
	defer fs.Close()

	// Arbitrary VIP the agent "dialed" — deliberately not any address
	// assigned to the stack (the stack has none).
	vip := netip.MustParseAddrPort("10.78.5.5:443")
	agent := netip.MustParseAddrPort("10.78.0.2:12345")

	const clientISN = 0x1000
	fs.InjectInbound(encodeTCP4(agent, vip, clientISN, 0, header.TCPFlagSyn))

	// Read the SYN-ACK the forwarder emits, so we can complete the handshake.
	readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer readCancel()
	synack := fs.ReadOutbound(readCtx)
	if synack == nil {
		t.Fatal("forwarder emitted no SYN-ACK: arbitrary-destination SYN was dropped (S-F1 not fixed)")
	}
	ip := header.IPv4(synack)
	if !ip.IsValid(len(synack)) {
		t.Fatalf("outbound packet is not valid IPv4 (len=%d)", len(synack))
	}
	// Verify the reply originates from the VIP — proof the stack accepted and
	// answered on a foreign (spoofed) address.
	if got := ip.DestinationAddress().String(); got != agent.Addr().String() {
		t.Fatalf("SYN-ACK dst = %q, want agent %q", got, agent.Addr())
	}
	tcpReply := header.TCP(synack[ip.HeaderLength():])
	if !tcpReply.Flags().Contains(header.TCPFlagSyn | header.TCPFlagAck) {
		t.Fatalf("expected SYN-ACK, got flags %v", tcpReply.Flags())
	}
	serverISN := tcpReply.SequenceNumber()

	// Complete the handshake: ACK with seq=clientISN+1, ack=serverISN+1.
	fs.InjectInbound(encodeTCP4(agent, vip, clientISN+1, serverISN+1, header.TCPFlagAck))

	select {
	case c := <-accepted:
		defer c.Close()
		got := c.LocalAddr().String()
		want := "10.78.5.5:443"
		if got != want {
			t.Fatalf("accepted conn LocalAddr = %q, want %q (original destination VIP)", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forwarder never delivered the accepted conn after handshake (S-F1 not fixed)")
	}
}

// TestForwarderRejectsGarbage feeds malformed and non-IP bytes to InjectInbound
// and asserts nothing panics.
func TestForwarderRejectsGarbage(t *testing.T) {
	fs, err := newForwardStack(1420, func(net.Conn) {
		t.Error("garbage input should not produce an accepted connection")
	}, nil)
	if err != nil {
		t.Fatalf("newForwardStack: %v", err)
	}
	defer fs.Close()

	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{0xff, 0xff, 0xff},
		{0x45},                                     // IPv4 nibble but truncated
		{0x60, 0x00, 0x00, 0x00},                   // IPv6 nibble but truncated
		{0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, // unknown version
	}
	for _, in := range inputs {
		fs.InjectInbound(in)
	}

	// Give the stack a moment; the callback must not have fired.
	time.Sleep(50 * time.Millisecond)
}
