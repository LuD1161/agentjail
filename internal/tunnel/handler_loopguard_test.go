package tunnel

// handler_loopguard_test.go — S-F3 tests: before dialing an upstream the gateway
// must refuse any target that resolves into the VIP pool (a crafted mapping or a
// hostname that resolves into 10.78.0.0/16 / fd78::/112), which would otherwise
// make the gateway dial back into its own forwarder (infinite interception loop
// / resource exhaustion). A normal public IP must pass the guard.

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

// runHandleConnResolver is like runHandleConn but lets the test inject a
// deterministic upstream resolver (g.lookupIP) so the S-F3 guard can be driven
// without real DNS.
func runHandleConnResolver(t *testing.T, port int, peek []byte, resolver func(string) ([]net.IP, error), want string) (*recordingHandler, *scriptedConn) {
	t.Helper()
	rec := &recordingHandler{}
	g := &Gateway{
		logger:   slog.New(rec),
		registry: dnsvip.NewRegistry(),
		lookupIP: resolver,
	}
	conn := &scriptedConn{
		readData: peek,
		local:    &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		remote:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000},
	}
	go g.handleConn(conn)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec.seen(want) {
			return rec, conn
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("handleConn never logged %q", want)
	return rec, conn
}

// A target whose upstream resolves into the VIP pool must be DENIED (loop guard)
// and never reach the "connection allowed, relaying" dial step.
func TestHandleConn_UpstreamInVIPPoolDenied(t *testing.T) {
	// Port 443 keeps the S-D1 fail-closed path out of the way; recognition
	// yields a benign TLS op that policy allows, so control reaches step 4.5.
	resolver := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.78.4.9")}, nil // inside 10.78.0.0/16
	}
	rec, _ := runHandleConnResolver(t, 443, []byte{0x16, 0x03, 0x01, 0x00, 0x2f}, resolver,
		"upstream resolves into the VIP pool; denying (loop guard)")

	if rec.seen("connection allowed, relaying") {
		t.Error("upstream inside the VIP pool was relayed — S-F3 loop guard not enforced")
	}
}

// An IPv6 upstream inside fd78::/112 must likewise be denied.
func TestHandleConn_UpstreamInVIPPoolV6Denied(t *testing.T) {
	resolver := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("fd78::abcd")}, nil
	}
	rec, _ := runHandleConnResolver(t, 443, []byte{0x16, 0x03, 0x01, 0x00, 0x2f}, resolver,
		"upstream resolves into the VIP pool; denying (loop guard)")

	if rec.seen("connection allowed, relaying") {
		t.Error("IPv6 upstream inside the VIP pool was relayed — S-F3 loop guard not enforced")
	}
}

// A normal public upstream IP must PASS the guard (reach the relay step). The
// upstream dial then fails fast on a bogus public IP, but that is after the
// guard has allowed it.
func TestHandleConn_PublicUpstreamAllowedThroughGuard(t *testing.T) {
	resolver := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil // example.com, public
	}
	rec, _ := runHandleConnResolver(t, 443, []byte{0x16, 0x03, 0x01, 0x00, 0x2f}, resolver,
		"connection allowed, relaying")

	if rec.seen("upstream resolves into the VIP pool; denying (loop guard)") {
		t.Error("public upstream IP was denied by the loop guard — S-F3 over-fired")
	}
}
