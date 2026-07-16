//go:build linux

package netns

import (
	"net"
	"testing"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

// The TUN address and the VIP pool are one address plan owned by dnsvip. When
// this file hardcoded the address instead of deriving it, the pool handed the
// same address to a hostname and that host's traffic never left the box.
// ADR 0034-platform-backend-shared-contract.
func TestTUNAddrIsTheReservedAgentAddress(t *testing.T) {
	ip, _, err := net.ParseCIDR(TUNAddrCIDR)
	if err != nil {
		t.Fatalf("TUNAddrCIDR %q is not a CIDR: %v", TUNAddrCIDR, err)
	}

	if want := dnsvip.AgentV4(); !ip.Equal(want) {
		t.Errorf("TUNAddrCIDR = %s, want the dnsvip-reserved agent address %s", ip, want)
	}

	// Reserved means the allocator must never hand it to a hostname.
	r := dnsvip.NewRegistry()
	for i := 0; i < 16; i++ {
		vip, err := r.Allocate(string(rune('a'+i)) + ".example.com")
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		if vip.Equal(ip) {
			t.Fatalf("VIP pool handed out the TUN's own address %s", vip)
		}
	}
}
