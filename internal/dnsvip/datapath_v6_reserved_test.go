package dnsvip

import "testing"

// The v6 datapath (fd79::1/fd79::2, AGE-262) must live outside poolV6
// (fd78::/112): a VIP-classified datapath address would trip the gateway's
// loop guard on its own traffic.
func TestV6DatapathAddressesAreOutsideThePool(t *testing.T) {
	r := NewRegistry()

	if r.IsVIP(GatewayV6()) {
		t.Errorf("IsVIP(%s) = true, want false — v6 gateway addr must stay outside the VIP pool", GatewayV6())
	}
	if r.IsVIP(AgentV6()) {
		t.Errorf("IsVIP(%s) = true, want false — v6 agent addr must stay outside the VIP pool", AgentV6())
	}
	if PoolV6().Contains(GatewayV6()) {
		t.Errorf("PoolV6 contains gateway v6 addr %s, want outside", GatewayV6())
	}
	if PoolV6().Contains(AgentV6()) {
		t.Errorf("PoolV6 contains agent v6 addr %s, want outside", AgentV6())
	}
}
