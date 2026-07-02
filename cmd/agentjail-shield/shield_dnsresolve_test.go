package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestResolveHostsToIPs_SlowHostDoesNotStallBatch verifies that a host whose
// (injected) lookup blocks past the per-lookup timeout does not stall
// resolution of the other hosts in the batch, and that the whole call
// returns well under the batch cap. This is a regression test for the
// original serial, no-timeout net.LookupHost loop that let one slow/
// unreachable DNS name stall the entire shield launch (and therefore
// `/mcp`).
func TestResolveHostsToIPs_SlowHostDoesNotStallBatch(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "fast.example.com":
			return []string{"93.184.216.34"}, nil
		case "slow.example.com":
			// Block until the caller's context is canceled (simulates a hung
			// DNS lookup) -- must not be allowed to block the batch.
			<-ctx.Done()
			return nil, ctx.Err()
		case "erroring.example.com":
			return nil, errors.New("no such host")
		default:
			t.Fatalf("unexpected host %q", host)
			return nil, nil
		}
	}

	start := time.Now()
	ips := resolveHostsToIPs(
		[]string{"fast.example.com", "slow.example.com", "erroring.example.com"},
		lookup,
		nil,
	)
	elapsed := time.Since(start)

	// dnsPerLookupTimeout is 2s; the batch must return at (or shortly after)
	// that bound, not wait for the full dnsBatchTimeout (5s) or hang forever.
	if elapsed >= dnsBatchTimeout {
		t.Fatalf("resolveHostsToIPs took %v, expected well under the %v batch cap", elapsed, dnsBatchTimeout)
	}

	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("expected only the fast host's IP, got %v", ips)
	}
}

// TestResolveHostsToIPs_DedupesAndSorts verifies the returned IP list is
// deduplicated and sorted, so profile generation is deterministic regardless
// of goroutine completion order.
func TestResolveHostsToIPs_DedupesAndSorts(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "a.example.com":
			return []string{"10.0.0.5", "10.0.0.1"}, nil
		case "b.example.com":
			return []string{"10.0.0.1", "10.0.0.9"}, nil
		default:
			t.Fatalf("unexpected host %q", host)
			return nil, nil
		}
	}

	ips := resolveHostsToIPs([]string{"a.example.com", "b.example.com"}, lookup, nil)

	want := []string{"10.0.0.1", "10.0.0.5", "10.0.0.9"}
	if len(ips) != len(want) {
		t.Fatalf("got %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("got %v, want %v", ips, want)
		}
	}
}

// TestResolveHostsToIPs_SkipsLoopback verifies loopback addresses returned
// by a lookup are excluded, matching prior resolveAllowedHosts behavior.
func TestResolveHostsToIPs_SkipsLoopback(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return []string{"127.0.0.1", "::1", "8.8.8.8"}, nil
	}
	ips := resolveHostsToIPs([]string{"localhost"}, lookup, nil)
	if len(ips) != 1 || ips[0] != "8.8.8.8" {
		t.Fatalf("expected only non-loopback IP, got %v", ips)
	}
}

// TestResolveHostsToIPs_EmptyInput verifies nil/empty input returns nil
// without invoking the lookup function.
func TestResolveHostsToIPs_EmptyInput(t *testing.T) {
	called := false
	lookup := func(ctx context.Context, host string) ([]string, error) {
		called = true
		return nil, nil
	}
	if ips := resolveHostsToIPs(nil, lookup, nil); ips != nil {
		t.Fatalf("expected nil, got %v", ips)
	}
	if called {
		t.Fatal("lookup should not be called for empty input")
	}
}
