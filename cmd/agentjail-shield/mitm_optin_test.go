package main

import "testing"

func boolPtr(b bool) *bool { return &b }

// Interception is on by default inside a tunnel, and off always wins.
// ADR 0077 (D2, D3).
func TestResolveMITM(t *testing.T) {
	tests := []struct {
		name             string
		mitmFlag, noMITM bool
		cfg              *bool
		want             bool
	}{
		{name: "default is on", want: true},
		{name: "--no-mitm forces transparent-only", noMITM: true, want: false},
		{name: "--mitm is redundant but harmless", mitmFlag: true, want: true},
		{name: "config false is a standing opt-out", cfg: boolPtr(false), want: false},
		{name: "config true is explicit opt-in", cfg: boolPtr(true), want: true},
		{name: "--mitm overrides a config opt-out", mitmFlag: true, cfg: boolPtr(false), want: true},
		{name: "--no-mitm overrides a config opt-in", noMITM: true, cfg: boolPtr(true), want: false},
		{name: "--no-mitm beats --mitm", mitmFlag: true, noMITM: true, want: false},
		{name: "--no-mitm beats everything", mitmFlag: true, noMITM: true, cfg: boolPtr(true), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveMITM(tt.mitmFlag, tt.noMITM, tt.cfg); got != tt.want {
				t.Errorf("resolveMITM(mitm=%t, noMITM=%t, cfg=%v) = %t, want %t",
					tt.mitmFlag, tt.noMITM, tt.cfg, got, tt.want)
			}
		})
	}
}

// Transparent-only must always be reachable in one flag, whatever the config
// says -- the escape hatch for cert-pinned endpoints. ADR 0077 (D2).
func TestTransparentOnlyAlwaysReachable(t *testing.T) {
	for _, cfg := range []*bool{nil, boolPtr(true), boolPtr(false)} {
		if resolveMITM(false, true, cfg) {
			t.Errorf("--no-mitm did not force transparent-only with cfg=%v", cfg)
		}
	}
}
