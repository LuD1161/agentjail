package tunnel

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

// chaosGWConfig returns a valid Config with the given WireGuard UDP listen port.
// Each call generates fresh keys, so multiple configs on the same port are
// independent from a key perspective.
func chaosGWConfig(t *testing.T, port int) Config {
	t.Helper()
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (priv): %v", err)
	}
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (pub): %v", err)
	}
	return Config{
		PrivateKey:    priv,
		ListenPort:    port,
		PeerPublicKey: pub,
		TunnelAddr:    "10.78.0.1/16",
	}
}

// TestChaosNilLogger verifies that passing nil logger falls back to slog.Default()
// and the gateway initialises without panicking.
func TestChaosNilLogger(t *testing.T) {
	cfg := chaosGWConfig(t, 51840)
	reg := dnsvip.NewRegistry()

	gw, err := NewGateway(cfg, reg, nil) // nil logger
	if err != nil {
		t.Fatalf("NewGateway with nil logger failed: %v", err)
	}
	defer gw.Close()

	if gw.logger == nil {
		t.Fatal("gateway.logger is nil after nil input")
	}
	if gw.logger != slog.Default() {
		t.Error("gateway.logger should equal slog.Default() when nil is passed")
	}
}

// TestChaosNilRegistry verifies that a nil registry is rejected at construction
// time rather than causing a nil-pointer panic inside handleConn later.
func TestChaosNilRegistry(t *testing.T) {
	cfg := chaosGWConfig(t, 51841)

	_, err := NewGateway(cfg, nil, nil)
	if err == nil {
		t.Fatal("NewGateway with nil registry: expected error, got nil")
	}
	t.Logf("nil-registry error (expected): %v", err)
}

// TestChaosCloseBeforeServe verifies that calling Close() on a gateway that
// has never entered ListenAndServe does not panic or return an error.
func TestChaosCloseBeforeServe(t *testing.T) {
	cfg := chaosGWConfig(t, 51842)
	reg := dnsvip.NewRegistry()

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	if err := gw.Close(); err != nil {
		t.Errorf("Close() before ListenAndServe returned error: %v", err)
	}
}

// TestChaosDoubleClose verifies that calling Close() twice is safe and does
// not panic or return an error on the second call.
func TestChaosDoubleClose(t *testing.T) {
	cfg := chaosGWConfig(t, 51843)
	reg := dnsvip.NewRegistry()

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	if err := gw.Close(); err != nil {
		t.Errorf("first Close(): %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Errorf("second Close() (should be no-op): %v", err)
	}
}

// TestChaosContextCancel starts ListenAndServe in a goroutine, cancels the
// context, and verifies the goroutine returns within a reasonable deadline
// with context.Canceled (or nil).
func TestChaosContextCancel(t *testing.T) {
	cfg := chaosGWConfig(t, 51844)
	reg := dnsvip.NewRegistry()

	gw, err := NewGateway(cfg, reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- gw.ListenAndServe(ctx)
	}()

	// Give the goroutine time to reach Accept().
	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case serveErr := <-done:
		if serveErr != nil && serveErr != context.Canceled {
			t.Errorf("ListenAndServe returned unexpected error: %v", serveErr)
		}
		t.Logf("ListenAndServe exited with: %v", serveErr)
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not shut down within 5 s after context cancel")
	}
}

// TestChaosPortCollision creates 5 gateways concurrently on the same WireGuard
// UDP port and asserts that at least one (and typically four) fail with a
// bind error.  All that succeed are closed afterwards.
func TestChaosPortCollision(t *testing.T) {
	const (
		n    = 5
		port = 51845
	)

	type result struct {
		gw  *Gateway
		err error
	}

	results := make(chan result, n)
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Generate keys inside goroutine so all configs share only the port.
			priv, _, kErr := GenerateKeyPair()
			if kErr != nil {
				results <- result{err: kErr}
				return
			}
			_, pub, kErr := GenerateKeyPair()
			if kErr != nil {
				results <- result{err: kErr}
				return
			}
			cfg := Config{
				PrivateKey:    priv,
				ListenPort:    port,
				PeerPublicKey: pub,
				TunnelAddr:    "10.78.0.1/16",
			}
			gw, gErr := NewGateway(cfg, dnsvip.NewRegistry(), nil)
			results <- result{gw: gw, err: gErr}
		}()
	}

	wg.Wait()
	close(results)

	var succeeded, failed int
	for r := range results {
		if r.err != nil {
			failed++
			t.Logf("gateway error (expected for collision): %v", r.err)
		} else {
			succeeded++
			r.gw.Close()
		}
	}

	t.Logf("port %d collision: %d succeeded, %d failed (out of %d)", port, succeeded, failed, n)

	if failed == 0 {
		t.Errorf("expected at least one error due to port collision on UDP %d, but all %d gateways succeeded", port, n)
	}
}

// TestChaosSmallMTU verifies that a gateway with the absolute minimum IP MTU
// (68 bytes) still initialises without error.
func TestChaosSmallMTU(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PrivateKey:    priv,
		ListenPort:    51846,
		PeerPublicKey: pub,
		TunnelAddr:    "10.78.0.1/16",
		MTU:           68, // absolute minimum IPv4 MTU (RFC 791)
	}

	gw, err := NewGateway(cfg, dnsvip.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewGateway with MTU=68 failed: %v", err)
	}
	defer gw.Close()

	if gw.cfg.MTU != 68 {
		t.Errorf("cfg.MTU = %d, want 68", gw.cfg.MTU)
	}
	if gw.cfg.mtu() != 68 {
		t.Errorf("mtu() = %d, want 68", gw.cfg.mtu())
	}
	t.Log("gateway initialised successfully with MTU=68")
}

// TestChaosLookupHost verifies that after Allocate, Lookup returns the exact
// hostname that was registered, and that repeated Allocate calls are idempotent.
func TestChaosLookupHost(t *testing.T) {
	reg := dnsvip.NewRegistry()

	hosts := []string{
		"chaos-db.internal",
		"chaos-cache.internal",
		"chaos-api.internal",
	}

	allocated := make(map[string]string) // hostname -> vip string

	for _, h := range hosts {
		vip, err := reg.Allocate(h)
		if err != nil {
			t.Fatalf("Allocate(%q): %v", h, err)
		}
		allocated[h] = vip.String()

		got, ok := reg.Lookup(vip)
		if !ok {
			t.Errorf("Lookup(%v) returned ok=false for host %q", vip, h)
			continue
		}
		if got != h {
			t.Errorf("Lookup(%v) = %q, want %q", vip, got, h)
		}
	}

	// Idempotency: second Allocate must return the same VIP.
	for _, h := range hosts {
		vip2, err := reg.Allocate(h)
		if err != nil {
			t.Fatalf("second Allocate(%q): %v", h, err)
		}
		if vip2.String() != allocated[h] {
			t.Errorf("second Allocate(%q) = %v, want %v (not idempotent)", h, vip2, allocated[h])
		}
	}

	// Verify VIPs are unique across hosts.
	seen := make(map[string]string)
	for h, vip := range allocated {
		if prev, dup := seen[vip]; dup {
			t.Errorf("VIP %v assigned to both %q and %q", vip, prev, h)
		}
		seen[vip] = h
	}

	t.Logf("allocated VIPs: %v", allocated)
}
