//go:build linux

package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

// TestAttachTUN_DrivesHandleConn is the end-to-end AttachTUN wiring test: a
// forward gateway built by NewForwardGateway, handed a (socketpair stand-in)
// TUN fd via AttachTUN, must pump a SYN written into the fd into its forwarder,
// pump the SYN-ACK back out the fd, and — once the handshake completes — run
// handleConn for the arbitrary destination VIP. We assert handleConn exercised
// the VIP-lookup path (registry miss) exactly as forward_gateway_test.go does,
// but this time the packets travel through the fd pump AttachTUN started rather
// than through InjectInbound/ReadOutbound directly.
func TestAttachTUN_DrivesHandleConn(t *testing.T) {
	const mtu = 1420

	rec := &recordingHandler{}
	logger := slog.New(rec)

	gw, err := NewForwardGateway(Config{MTU: mtu}, dnsvip.NewRegistry(), logger)
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}
	defer gw.Close()

	pumpEnd, testEnd := socketpairFiles(t)
	defer pumpEnd.Close()
	defer testEnd.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := gw.AttachTUN(ctx, pumpEnd); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}

	// Arbitrary VIP the agent "dialed" — deliberately unregistered so the VIP
	// lookup inside handleConn misses and emits the warning we assert on.
	vip := netip.MustParseAddrPort("10.78.7.7:443")
	agent := netip.MustParseAddrPort("10.78.0.2:12345")

	// 1. Write the SYN into the test fd end; the inbound pump injects it.
	const clientISN = 0x3000
	if _, err := testEnd.Write(encodeTCP4(agent, vip, clientISN, 0, header.TCPFlagSyn)); err != nil {
		t.Fatalf("write SYN: %v", err)
	}

	// 2. Read the SYN-ACK the outbound pump writes back out the fd.
	if err := testEnd.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, mtu)
	n, err := testEnd.Read(buf)
	if err != nil {
		t.Fatalf("read SYN-ACK from fd: %v (AttachTUN pump did not round-trip the reply)", err)
	}
	synack := buf[:n]
	ip := header.IPv4(synack)
	if !ip.IsValid(len(synack)) {
		t.Fatalf("outbound packet is not valid IPv4 (len=%d)", len(synack))
	}
	tcpReply := header.TCP(synack[ip.HeaderLength():])
	if !tcpReply.Flags().Contains(header.TCPFlagSyn | header.TCPFlagAck) {
		t.Fatalf("expected SYN-ACK, got flags %v", tcpReply.Flags())
	}
	serverISN := tcpReply.SequenceNumber()

	// 3. Complete the handshake; only then does handleConn come alive.
	if _, err := testEnd.Write(encodeTCP4(agent, vip, clientISN+1, serverISN+1, header.TCPFlagAck)); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	// 4. handleConn should run and log the registry-miss warning.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec.seen("no VIP mapping for destination") {
			return // handleConn ran via the AttachTUN pump path.
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("handleConn never ran for the SYN pumped through AttachTUN")
}

// TestAttachTUN_RequiresForwardGateway verifies AttachTUN refuses a gateway
// that has no forward stack (i.e. not built with NewForwardGateway).
func TestAttachTUN_RequiresForwardGateway(t *testing.T) {
	g := &Gateway{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// fwd is nil, so AttachTUN must error before touching the fd; nil f is fine.
	if err := g.AttachTUN(context.Background(), nil); err == nil {
		t.Fatal("AttachTUN on a non-forward gateway returned nil error")
	}
}

// TestAttachTUN_CloseStopsPump verifies Gateway.Close stops the pump started by
// AttachTUN cleanly, promptly, and without leaking goroutines even when the
// inbound loop is blocked on an idle fd Read. A leaked/hung pump would trip the
// surrounding timeout guard.
func TestAttachTUN_CloseStopsPump(t *testing.T) {
	gw, err := NewForwardGateway(Config{MTU: 1420}, dnsvip.NewRegistry(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}

	pumpEnd, testEnd := socketpairFiles(t)
	defer pumpEnd.Close()
	defer testEnd.Close()

	if err := gw.AttachTUN(context.Background(), pumpEnd); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- gw.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return: AttachTUN pump goroutines leaked / inbound Read not interrupted")
	}

	// Close is idempotent and must not double-close the pump.
	if err := gw.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

// TestAttachTUN_DetachStopsPump verifies detachTUN stops the pump and leaves the
// gateway able to Close cleanly afterward (no double-close of the pump).
func TestAttachTUN_DetachStopsPump(t *testing.T) {
	gw, err := NewForwardGateway(Config{MTU: 1420}, dnsvip.NewRegistry(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}
	defer gw.Close()

	pumpEnd, testEnd := socketpairFiles(t)
	defer pumpEnd.Close()
	defer testEnd.Close()

	if err := gw.AttachTUN(context.Background(), pumpEnd); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}

	done := make(chan struct{})
	go func() { gw.detachTUN(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("detachTUN did not return: pump goroutines leaked")
	}
}
