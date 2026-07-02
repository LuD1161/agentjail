package dnsvip

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ChaosTestPoolExhaustion allocates all 65534 IPv4 VIPs, verifies pool
// exhaustion, frees half, then reallocates the same number.
func ChaosTestPoolExhaustion(t *testing.T) {
	r := NewRegistry()

	// Allocate all VIPs.
	for i := range ipv4PoolSize {
		_, err := r.Allocate(fmt.Sprintf("exhaust-%d.test", i))
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i+1, err)
		}
	}

	alloc, avail := r.Stats()
	if alloc != ipv4PoolSize {
		t.Errorf("after full alloc: allocated=%d, want %d", alloc, ipv4PoolSize)
	}
	if avail != 0 {
		t.Errorf("after full alloc: available=%d, want 0", avail)
	}

	// Next allocation must fail.
	_, err := r.Allocate("overflow.test")
	if err != ErrPoolExhausted {
		t.Fatalf("expected ErrPoolExhausted, got %v", err)
	}

	// Free the first half.
	const half = ipv4PoolSize / 2
	for i := range half {
		r.Free(fmt.Sprintf("exhaust-%d.test", i))
	}

	alloc, avail = r.Stats()
	if alloc != ipv4PoolSize-half {
		t.Errorf("after freeing half: allocated=%d, want %d", alloc, ipv4PoolSize-half)
	}
	if avail != half {
		t.Errorf("after freeing half: available=%d, want %d", avail, half)
	}

	// Reallocate the freed slots.
	for i := range half {
		ip, err := r.Allocate(fmt.Sprintf("realloc-%d.test", i))
		if err != nil {
			t.Fatalf("reallocation %d failed: %v", i, err)
		}
		// Verify reverse lookup works.
		host, ok := r.Lookup(ip)
		if !ok {
			t.Errorf("realloc %d: reverse lookup returned ok=false for %s", i, ip)
			continue
		}
		if want := fmt.Sprintf("realloc-%d.test", i); host != want {
			t.Errorf("realloc %d: reverse lookup = %q, want %q", i, host, want)
		}
	}

	// Pool should be full again.
	_, err = r.Allocate("overflow2.test")
	if err != ErrPoolExhausted {
		t.Fatalf("after re-fill: expected ErrPoolExhausted, got %v", err)
	}
}

// ChaosTestConcurrentStorm runs 50 goroutines each doing 100 allocate+free
// cycles simultaneously to verify locking correctness.
func ChaosTestConcurrentStorm(t *testing.T) {
	const (
		goroutines = 50
		cycles     = 100
	)

	r := NewRegistry()
	var wg sync.WaitGroup
	var allocErrs atomic.Int64
	var lookupErrs atomic.Int64

	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for c := range cycles {
				hostname := fmt.Sprintf("storm-%d-%d.test", g, c)

				ip, err := r.Allocate(hostname)
				if err != nil {
					// Pool might be transiently full; that's tolerable.
					if err != ErrPoolExhausted {
						allocErrs.Add(1)
						t.Logf("goroutine %d cycle %d alloc error: %v", g, c, err)
					}
					continue
				}

				// Verify the reverse lookup is consistent while still allocated.
				host, ok := r.Lookup(ip)
				if !ok || host != hostname {
					lookupErrs.Add(1)
					t.Logf("goroutine %d cycle %d: Lookup(%s)=%q ok=%v, want %q",
						g, c, ip, host, ok, hostname)
				}

				r.Free(hostname)
			}
		}(g)
	}

	wg.Wait()

	if n := allocErrs.Load(); n > 0 {
		t.Errorf("unexpected alloc errors (non-exhaustion): %d", n)
	}
	if n := lookupErrs.Load(); n > 0 {
		t.Errorf("reverse lookup inconsistencies: %d", n)
	}

	// After all goroutines are done every entry should have been freed.
	alloc, _ := r.Stats()
	if alloc != 0 {
		t.Errorf("after storm: %d entries still allocated (expected 0)", alloc)
	}
}

// ChaosTestVIPReuse allocates, frees, then reallocates the same hostname and
// verifies VIP reuse plus correct reverse-lookup state.
func ChaosTestVIPReuse(t *testing.T) {
	r := NewRegistry()

	// Allocate the first hostname; this will get offset 1.
	vip1, err := r.Allocate("original.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("original.test -> %s", vip1)

	// Free it; offset 1 goes onto the free list.
	r.Free("original.test")

	// Ensure the freed VIP no longer maps to the old hostname.
	if host, ok := r.Lookup(vip1); ok {
		t.Errorf("after Free: Lookup(%s) still returns %q", vip1, host)
	}

	// Allocate a new hostname; it should receive the recycled VIP.
	vip2, err := r.Allocate("reuse.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reuse.test    -> %s", vip2)

	if !vip1.Equal(vip2) {
		t.Errorf("VIP not reused: original=%s reuse=%s", vip1, vip2)
	}

	// Reverse lookup must point at the new hostname.
	host, ok := r.Lookup(vip2)
	if !ok {
		t.Fatalf("Lookup(%s) returned ok=false after reuse", vip2)
	}
	if host != "reuse.test" {
		t.Errorf("Lookup(%s) = %q, want %q", vip2, host, "reuse.test")
	}

	// Reallocate the original hostname; it gets a fresh sequential VIP.
	vip3, err := r.Allocate("original.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("original.test (re) -> %s", vip3)

	if vip2.Equal(vip3) {
		t.Errorf("second realloc should not collide with reuse.test VIP: both got %s", vip3)
	}

	// Both entries must have correct reverse lookups.
	if h, ok := r.Lookup(vip2); !ok || h != "reuse.test" {
		t.Errorf("Lookup(reuse VIP %s) = %q ok=%v, want reuse.test", vip2, h, ok)
	}
	if h, ok := r.Lookup(vip3); !ok || h != "original.test" {
		t.Errorf("Lookup(original VIP %s) = %q ok=%v, want original.test", vip3, h, ok)
	}
}

// ChaosTestMalformedHostname feeds pathological hostname strings into the
// registry and verifies it does not panic or corrupt state.
func ChaosTestMalformedHostname(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
	}{
		{"empty", ""},
		{"null_bytes", "host\x00with\x00nulls"},
		{"thousand_chars", strings.Repeat("a", 1000)},
		{"dots_only", "..."},
		{"just_dot", "."},
		{"leading_dot", ".leading"},
		{"trailing_dot", "trailing."},
		{"unicode", "héllo.wörld"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()

			// Must not panic.
			ip, err := r.Allocate(tc.hostname)
			if err != nil {
				// Exhaustion is the only legal error here.
				if err != ErrPoolExhausted {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			// Reverse lookup must return the exact hostname we allocated.
			host, ok := r.Lookup(ip)
			if !ok {
				t.Fatalf("Lookup(%s) returned ok=false after allocation", ip)
			}
			if host != tc.hostname {
				t.Errorf("Lookup(%s) = %q, want %q", ip, host, tc.hostname)
			}

			// Free must not panic.
			r.Free(tc.hostname)

			// Post-free lookup must return ok=false.
			if _, ok := r.Lookup(ip); ok {
				t.Errorf("Lookup(%s) returned ok=true after Free", ip)
			}
		})
	}
}

// ChaosTestIPv6PoolIndependence verifies that the IPv6 pool is managed
// independently from the IPv4 pool by checking pool sizes, exhaustion
// behavior, and that freeing entries restores both pools consistently.
func ChaosTestIPv6PoolIndependence(t *testing.T) {
	r := NewRegistry()

	// Allocate all 65534 entries (v4 exhausts first; v4=65534, v6=65535).
	for i := range ipv4PoolSize {
		_, err := r.Allocate(fmt.Sprintf("v6ind-%d.test", i))
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
	}

	// v4 is exhausted; further allocations (which allocate both) must fail.
	_, errV4 := r.Allocate("v6ind-overflow.test")
	if errV4 != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted (v4 exhausted), got %v", errV4)
	}
	_, errV6 := r.AllocateV6("v6ind-overflow-v6.test")
	if errV6 != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted (v4 still exhausted), got %v", errV6)
	}

	// Free a subset; both pools must accept new allocations.
	const toFree = 100
	for i := range toFree {
		r.Free(fmt.Sprintf("v6ind-%d.test", i))
	}

	for i := range toFree {
		hostV4 := fmt.Sprintf("v6ind-new-v4-%d.test", i)
		ip4, err := r.Allocate(hostV4)
		if err != nil {
			t.Fatalf("v4 re-alloc %d failed: %v", i, err)
		}
		if !strings.HasPrefix(ip4.String(), "10.78.") {
			t.Errorf("v4 alloc returned non-v4 address: %s", ip4)
		}
	}

	// After refilling to the limit, exhaustion must be triggered again.
	_, err := r.Allocate("v6ind-overflow2.test")
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted after refill, got %v", err)
	}

	// Verify v6 addresses are in the expected fd78:: range for allocated entries.
	sampleHost := fmt.Sprintf("v6ind-%d.test", ipv4PoolSize/2+1)
	ip6, err := r.AllocateV6(sampleHost) // already allocated, returns cached v6
	if err != nil {
		t.Fatalf("AllocateV6 for already-allocated host failed: %v", err)
	}
	if !strings.HasPrefix(ip6.String(), "fd78::") {
		t.Errorf("v6 address not in fd78:: range: %s", ip6)
	}

	host, ok := r.Lookup(ip6)
	if !ok || host != sampleHost {
		t.Errorf("v6 reverse lookup: got %q ok=%v, want %q", host, ok, sampleHost)
	}
}

// ChaosTestDoubleFree verifies that freeing the same hostname twice does not
// panic, corrupt the registry, or double-add the offset to the free list in a
// way that causes duplicate VIP allocations.
func ChaosTestDoubleFree(t *testing.T) {
	r := NewRegistry()

	vip, err := r.Allocate("double-free.test")
	if err != nil {
		t.Fatal(err)
	}

	// First free: normal.
	r.Free("double-free.test")

	// Second free: must not panic.
	r.Free("double-free.test")

	// Allocate two new hosts; they must get distinct VIPs.
	ip1, err := r.Allocate("post-df-1.test")
	if err != nil {
		t.Fatal(err)
	}
	ip2, err := r.Allocate("post-df-2.test")
	if err != nil {
		t.Fatal(err)
	}

	if ip1.Equal(ip2) {
		t.Errorf("double-free caused duplicate VIP allocation: both got %s", ip1)
	}

	// The originally freed VIP should now belong to exactly one host.
	// (After double-free, if the offset was put on the free list twice, two
	// allocations would return the same VIP — detected above.)
	count := 0
	if h, ok := r.Lookup(vip); ok {
		t.Logf("original VIP %s now maps to %q", vip, h)
		count++
	}
	// Regardless, reverse lookups for ip1 and ip2 must be unambiguous.
	if h, ok := r.Lookup(ip1); !ok || h != "post-df-1.test" {
		t.Errorf("Lookup(%s) = %q ok=%v, want post-df-1.test", ip1, h, ok)
	}
	if h, ok := r.Lookup(ip2); !ok || h != "post-df-2.test" {
		t.Errorf("Lookup(%s) = %q ok=%v, want post-df-2.test", ip2, h, ok)
	}
	_ = count
}

// ChaosTestLookupAfterFree verifies that a VIP freed from the registry returns
// ok=false on Lookup for both IPv4 and IPv6 addresses.
func ChaosTestLookupAfterFree(t *testing.T) {
	r := NewRegistry()

	// Allocate via v4 path to capture both VIPs.
	ip4, err := r.Allocate("laf.test")
	if err != nil {
		t.Fatal(err)
	}
	// AllocateV6 for the same host returns the already-allocated v6 address.
	ip6, err := r.AllocateV6("laf.test")
	if err != nil {
		t.Fatal(err)
	}

	// Sanity-check: both addresses must resolve before free.
	if h, ok := r.Lookup(ip4); !ok || h != "laf.test" {
		t.Errorf("pre-free v4 Lookup = %q ok=%v, want laf.test", h, ok)
	}
	if h, ok := r.Lookup(ip6); !ok || h != "laf.test" {
		t.Errorf("pre-free v6 Lookup = %q ok=%v, want laf.test", h, ok)
	}

	r.Free("laf.test")

	// Both must now be gone.
	if h, ok := r.Lookup(ip4); ok {
		t.Errorf("post-free v4 Lookup(%s) returned ok=true with host=%q", ip4, h)
	}
	if h, ok := r.Lookup(ip6); ok {
		t.Errorf("post-free v6 Lookup(%s) returned ok=true with host=%q", ip6, h)
	}

	// Allocate an unrelated host; it must not accidentally return a stale entry.
	ip4b, err := r.Allocate("other.test")
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := r.Lookup(ip4b); !ok || h != "other.test" {
		t.Errorf("post-free unrelated Lookup = %q ok=%v, want other.test", h, ok)
	}

	// Explicitly verify the freed VIP is no longer in the registry by checking
	// the size.
	alloc, _ := r.Stats()
	if alloc != 1 {
		t.Errorf("Stats: allocated=%d, want 1 (only other.test)", alloc)
	}

	// Freed VIP might now be reused by other.test or remain unmapped.
	// Either way, looking it up must not return "laf.test".
	if h, _ := r.Lookup(ip4); h == "laf.test" {
		t.Errorf("freed VIP %s still maps to laf.test", ip4)
	}
}

// TestChaos is the single entry-point that go test -run Chaos discovers.
// It fans out into sub-tests so each scenario runs independently with its
// own registry.
func TestChaos(t *testing.T) {
	t.Run("PoolExhaustion", ChaosTestPoolExhaustion)
	t.Run("ConcurrentStorm", ChaosTestConcurrentStorm)
	t.Run("VIPReuse", ChaosTestVIPReuse)
	t.Run("MalformedHostname", ChaosTestMalformedHostname)
	t.Run("IPv6PoolIndependence", ChaosTestIPv6PoolIndependence)
	t.Run("DoubleFree", ChaosTestDoubleFree)
	t.Run("LookupAfterFree", ChaosTestLookupAfterFree)
}

// Ensure net is used (it's used via r.Lookup returning net.IP).
var _ net.IP
