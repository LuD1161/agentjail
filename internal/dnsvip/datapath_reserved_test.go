package dnsvip

import (
	"net"
	"testing"
)

// The datapath addresses live inside the VIP pool, so the allocator has to skip
// them. It did not: the 2nd distinct hostname of every tunneled session got
// 10.78.0.2 — the agent's own TUN address — and its traffic never left the box.
// Only that one host failed, which read as flakiness rather than a bug.
func TestAllocateNeverReturnsDatapathAddress(t *testing.T) {
	r := NewRegistry()

	reserved := map[string]string{
		GatewayV4().String(): "gateway/DNS address",
		AgentV4().String():   "agent TUN address",
	}

	// Well past the first few offsets, where the collision lived.
	for i := 0; i < 100; i++ {
		host := "host" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.com"
		vip, err := r.Allocate(host)
		if err != nil {
			t.Fatalf("Allocate(%s): %v", host, err)
		}
		if what, bad := reserved[vip.String()]; bad {
			t.Fatalf("Allocate(%s) returned %s — that is the %s, not a VIP; "+
				"traffic to it never leaves the namespace", host, vip, what)
		}
	}
}

// The first hostname must land above the datapath, not on it.
func TestFirstAllocationSkipsDatapath(t *testing.T) {
	r := NewRegistry()

	vip, err := r.Allocate("first.example.com")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if want := (net.IP{10, 78, 0, 3}); !vip.Equal(want) {
		t.Errorf("first VIP = %s, want %s (.1 gateway and .2 agent TUN are reserved)", vip, want)
	}
}

// The reserved addresses must still be inside the pool: the gateway's loop
// guard rejects upstream dials into the pool CIDR, and the datapath depends on
// that staying true.
func TestDatapathAddressesAreInsideThePool(t *testing.T) {
	r := NewRegistry()
	for _, ip := range []net.IP{GatewayV4(), AgentV4()} {
		if !r.IsVIP(ip) {
			t.Errorf("IsVIP(%s) = false, want true — datapath must stay inside the pool CIDR", ip)
		}
	}
}
