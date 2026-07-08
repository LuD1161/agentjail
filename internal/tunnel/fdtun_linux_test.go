//go:build linux

package tunnel

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// socketpairFiles returns two *os.File ends of an AF_UNIX SOCK_DGRAM
// socketpair. SOCK_DGRAM preserves one-write-one-read framing, standing in for
// a Linux TUN device's IFF_NO_PI "one IP packet per Read" behavior. os.NewFile
// makes each end pollable, so read/write deadlines work.
func socketpairFiles(t *testing.T) (pumpEnd, testEnd *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// A blocking fd makes os.NewFile treat the file as non-pollable, which
	// disables read/write deadlines. Set both ends nonblocking so os.NewFile
	// registers them with the runtime poller — matching how a real TUN device
	// is opened (O_NONBLOCK) and enabling the deadline-based shutdown nudge.
	for _, fd := range fds {
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatalf("set nonblock: %v", err)
		}
	}
	pumpEnd = os.NewFile(uintptr(fds[0]), "tun-pump")
	testEnd = os.NewFile(uintptr(fds[1]), "tun-test")
	if pumpEnd == nil || testEnd == nil {
		t.Fatal("os.NewFile returned nil for a socketpair fd")
	}
	return pumpEnd, testEnd
}

// TestFdPumpDrivesHandshake is the end-to-end fd→inject→handshake test: a raw
// IPv4 TCP SYN written into the fd is pumped into the forwardStack, the SYN-ACK
// the stack emits is pumped back out the fd, and completing the handshake
// surfaces an accepted conn whose LocalAddr() is the original VIP. This proves
// the fd<->forwarder bridge round-trips packets in both directions.
func TestFdPumpDrivesHandshake(t *testing.T) {
	const mtu = 1420

	pumpEnd, testEnd := socketpairFiles(t)
	defer pumpEnd.Close()
	defer testEnd.Close()

	accepted := make(chan net.Conn, 1)
	fs, err := newForwardStack(mtu, func(c net.Conn) {
		accepted <- c
	})
	if err != nil {
		t.Fatalf("newForwardStack: %v", err)
	}
	defer fs.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pump := newFdPump(pumpEnd, fs, mtu)
	pump.Start(ctx)
	defer pump.Close()

	// The agent "dialed" an arbitrary VIP that is not any address the stack
	// owns — the whole point of the transparent forwarder.
	vip := netip.MustParseAddrPort("10.78.9.9:443")
	agent := netip.MustParseAddrPort("10.78.0.2:12345")

	// 1. Write the SYN into the test's fd end; the inbound pump injects it.
	const clientISN = 0x1000
	syn := encodeTCP4(agent, vip, clientISN, 0, header.TCPFlagSyn)
	if _, err := testEnd.Write(syn); err != nil {
		t.Fatalf("write SYN: %v", err)
	}

	// 2. Read the SYN-ACK the outbound pump writes back out the fd.
	if err := testEnd.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, mtu)
	n, err := testEnd.Read(buf)
	if err != nil {
		t.Fatalf("read SYN-ACK from fd: %v (pump did not round-trip the reply)", err)
	}
	synack := buf[:n]

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

	// 3. Complete the handshake: ACK with seq=clientISN+1, ack=serverISN+1.
	ack := encodeTCP4(agent, vip, clientISN+1, serverISN+1, header.TCPFlagAck)
	if _, err := testEnd.Write(ack); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	// 4. The accept callback must fire with the original destination VIP.
	select {
	case c := <-accepted:
		defer c.Close()
		if got, want := c.LocalAddr().String(), "10.78.9.9:443"; got != want {
			t.Fatalf("accepted conn LocalAddr = %q, want %q (original destination VIP)", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pump never delivered the accepted conn after handshake")
	}
}

// TestFdPumpCloseIsClean verifies Close stops both pump goroutines and returns
// promptly even while the inbound loop is blocked on a Read (no fd traffic, no
// prior ctx cancel). Close must be self-terminating: it cancels the outbound
// loop and nudges the inbound Read via a read deadline. If Close leaked or
// hung, the surrounding timeout guard fails the test.
func TestFdPumpCloseIsClean(t *testing.T) {
	const mtu = 1420

	pumpEnd, testEnd := socketpairFiles(t)
	defer pumpEnd.Close()
	defer testEnd.Close()

	fs, err := newForwardStack(mtu, func(net.Conn) {
		t.Error("no connection should be accepted in the close test")
	})
	if err != nil {
		t.Fatalf("newForwardStack: %v", err)
	}
	defer fs.Close()

	pump := newFdPump(pumpEnd, fs, mtu)
	pump.Start(context.Background())

	done := make(chan struct{})
	go func() {
		_ = pump.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pump.Close did not return: goroutines leaked / inbound Read not interrupted")
	}
}
