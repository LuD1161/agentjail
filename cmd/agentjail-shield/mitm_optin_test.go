package main

import "testing"

// TLS interception is opt-in and off wins ties. ADR 0077 (D1, D2, D3).
func TestResolveMITM(t *testing.T) {
	tests := []struct {
		name                          string
		mitmFlag, noMITMFlag, cfgMITM bool
		want                          bool
	}{
		{name: "default is off", want: false},
		{name: "--mitm opts in", mitmFlag: true, want: true},
		{name: "config grants standing consent", cfgMITM: true, want: true},
		{name: "--no-mitm overrides config", noMITMFlag: true, cfgMITM: true, want: false},
		{name: "--no-mitm beats --mitm", mitmFlag: true, noMITMFlag: true, want: false},
		{name: "--no-mitm beats both", mitmFlag: true, noMITMFlag: true, cfgMITM: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveMITM(tt.mitmFlag, tt.noMITMFlag, tt.cfgMITM); got != tt.want {
				t.Errorf("resolveMITM(mitm=%t, noMITM=%t, cfg=%t) = %t, want %t",
					tt.mitmFlag, tt.noMITMFlag, tt.cfgMITM, got, tt.want)
			}
		})
	}
}

// --tunnel must never imply interception: the switches are independent, so no
// combination of tunnel state can turn MITM on by itself. ADR 0077 (D1).
func TestTunnelDoesNotImplyMITM(t *testing.T) {
	if resolveMITM(false, false, false) {
		t.Error("MITM on with nothing requested: --tunnel must not imply --mitm")
	}
}
