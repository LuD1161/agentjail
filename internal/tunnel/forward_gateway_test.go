package tunnel

// forward_gateway_test.go — tests for the transparent forward gateway
// (NewForwardGateway, S-F1) and handleConn panic isolation (S-F2).

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

// recordingHandler is a minimal slog.Handler that captures every log record's
// message so a test can assert a particular code path emitted a log line.
type recordingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) seen(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.msgs {
		if m == substr {
			return true
		}
	}
	return false
}

// TestForwardGateway_HandleConnRunsForInjectedSYN is the S-F1 wiring test: a
// forward gateway built by NewForwardGateway must run handleConn for a SYN to
// an arbitrary VIP destination injected through the gateway's own
// InjectInbound. We drive the full 3-way handshake (as forwarder_test.go does)
// and then assert that handleConn exercised the VIP-lookup path — the injected
// destination is not in the registry, so handleConn logs the registry-miss
// warning before it blocks on the (empty) peek read.
func TestForwardGateway_HandleConnRunsForInjectedSYN(t *testing.T) {
	rec := &recordingHandler{}
	logger := slog.New(rec)

	reg := dnsvip.NewRegistry()

	gw, err := NewForwardGateway(Config{MTU: 1420}, reg, logger)
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}
	defer gw.Close()

	if gw.fwd == nil {
		t.Fatal("forward gateway has nil forwardStack")
	}

	// Arbitrary VIP the agent "dialed" — deliberately not registered, so the
	// VIP lookup inside handleConn misses and emits the warning we assert on.
	vip := netip.MustParseAddrPort("10.78.5.5:443")
	agent := netip.MustParseAddrPort("10.78.0.2:12345")

	const clientISN = 0x2000
	gw.InjectInbound(encodeTCP4(agent, vip, clientISN, 0, header.TCPFlagSyn))

	readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer readCancel()
	synack := gw.ReadOutbound(readCtx)
	if synack == nil {
		t.Fatal("forward gateway emitted no SYN-ACK: arbitrary-destination SYN dropped (S-F1 not wired)")
	}
	ip := header.IPv4(synack)
	if !ip.IsValid(len(synack)) {
		t.Fatalf("outbound packet is not valid IPv4 (len=%d)", len(synack))
	}
	tcpReply := header.TCP(synack[ip.HeaderLength():])
	if !tcpReply.Flags().Contains(header.TCPFlagSyn | header.TCPFlagAck) {
		t.Fatalf("expected SYN-ACK, got flags %v", tcpReply.Flags())
	}
	serverISN := tcpReply.SequenceNumber()

	// Complete the handshake; only then does the endpoint (and handleConn via
	// the accept callback) come alive.
	gw.InjectInbound(encodeTCP4(agent, vip, clientISN+1, serverISN+1, header.TCPFlagAck))

	// handleConn should run and log the registry-miss warning before blocking
	// on the peek read. Poll for it.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec.seen("no VIP mapping for destination") {
			return // handleConn ran and exercised the VIP-lookup path.
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("handleConn never ran for the injected SYN (VIP-lookup path not exercised)")
}

// TestForwardGateway_ServeBlocksUntilContextDone verifies the forward serve
// path blocks until ctx is cancelled and then returns, tearing the stack down.
func TestForwardGateway_ServeBlocksUntilContextDone(t *testing.T) {
	gw, err := NewForwardGateway(Config{MTU: 1420}, dnsvip.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}
	defer gw.Close() // idempotent with the serveForward-driven Close.

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gw.ListenAndServe(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Errorf("ListenAndServe returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward ListenAndServe did not return within 5s of context cancel")
	}
}

// panicConn is a net.Conn whose RemoteAddr is not a *net.TCPAddr, so the type
// assertion at the top of handleConn panics — a stand-in for any panic on
// attacker-controlled input.
type panicConn struct {
	mu     sync.Mutex
	closed bool
}

func (p *panicConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (p *panicConn) Write([]byte) (int, error) { return 0, io.EOF }
func (p *panicConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// RemoteAddr returns a *net.UDPAddr, so `c.RemoteAddr().(*net.TCPAddr)` panics.
func (p *panicConn) RemoteAddr() net.Addr             { return &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5} }
func (p *panicConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9} }
func (p *panicConn) SetDeadline(time.Time) error      { return nil }
func (p *panicConn) SetReadDeadline(time.Time) error  { return nil }
func (p *panicConn) SetWriteDeadline(time.Time) error { return nil }

func (p *panicConn) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// TestHandleConn_PanicIsContained is the S-F2 test: a panic inside handleConn
// must be recovered (never propagate, never crash), and the connection must be
// closed — i.e. the traffic is denied.
func TestHandleConn_PanicIsContained(t *testing.T) {
	g := &Gateway{
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		registry: dnsvip.NewRegistry(),
	}

	pc := &panicConn{}

	// If the panic escaped, this call would crash the test binary. The deferred
	// recover in handleConn must prevent that.
	g.handleConn(pc)

	if !pc.isClosed() {
		t.Error("panicking connection was not closed — deny not enforced (S-F2)")
	}
}
