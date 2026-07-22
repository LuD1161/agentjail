package shieldapp

import "testing"

// Mirrors mitm_optin_test.go's TestResolveMITM for the tunnel IPv6 knob
// (AGE-262). Off by default, and the precedence is CLI > env > config >
// default, with --no-tunnel-ipv6 beating everything. ADR 0110.
func TestResolveTunnelIPv6(t *testing.T) {
	tests := []struct {
		name                 string
		ipv6Flag, noIPv6Flag bool
		envSet               bool
		cfg                  *bool
		want                 bool
	}{
		{name: "default is off", want: false},
		{name: "--tunnel-ipv6 turns it on", ipv6Flag: true, want: true},
		{name: "--no-tunnel-ipv6 is redundant but harmless", noIPv6Flag: true, want: false},
		{name: "env var turns it on", envSet: true, want: true},
		{name: "config true is a standing opt-in", cfg: boolPtr(true), want: true},
		{name: "config false is a standing opt-out", cfg: boolPtr(false), want: false},
		{name: "env overrides a config opt-out", envSet: true, cfg: boolPtr(false), want: true},
		{name: "config wins over default when env absent", cfg: boolPtr(true), want: true},
		{name: "--tunnel-ipv6 overrides env absent, config opt-out", ipv6Flag: true, cfg: boolPtr(false), want: true},
		{name: "--tunnel-ipv6 overrides env", ipv6Flag: false, noIPv6Flag: false, envSet: true, want: true},
		{name: "--no-tunnel-ipv6 overrides env", noIPv6Flag: true, envSet: true, want: false},
		{name: "--no-tunnel-ipv6 overrides config opt-in", noIPv6Flag: true, cfg: boolPtr(true), want: false},
		{name: "--no-tunnel-ipv6 beats --tunnel-ipv6", ipv6Flag: true, noIPv6Flag: true, want: false},
		{name: "--no-tunnel-ipv6 beats everything", ipv6Flag: true, noIPv6Flag: true, envSet: true, cfg: boolPtr(true), want: false},
		{name: "--tunnel-ipv6 beats env and config opt-out", ipv6Flag: true, envSet: true, cfg: boolPtr(false), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTunnelIPv6(tt.ipv6Flag, tt.noIPv6Flag, tt.envSet, tt.cfg)
			if got != tt.want {
				t.Errorf("resolveTunnelIPv6(flag=%t, noFlag=%t, envSet=%t, cfg=%v) = %t, want %t",
					tt.ipv6Flag, tt.noIPv6Flag, tt.envSet, tt.cfg, got, tt.want)
			}
		})
	}
}

// The escape hatch must always be reachable: --no-tunnel-ipv6 forces the v4
// datapath whatever env/config say. Mirrors TestTransparentOnlyAlwaysReachable.
func TestTunnelIPv6OffAlwaysReachable(t *testing.T) {
	for _, cfg := range []*bool{nil, boolPtr(true), boolPtr(false)} {
		for _, envSet := range []bool{false, true} {
			if resolveTunnelIPv6(true, true, envSet, cfg) {
				t.Errorf("--no-tunnel-ipv6 did not force v4-only with envSet=%t cfg=%v", envSet, cfg)
			}
		}
	}
}
