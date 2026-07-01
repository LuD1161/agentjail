//go:build linux

package main

import "testing"

// ---- FIX4: Linux inspectable Landlock network plan (ADR 0039) ----
//
// buildLandlockNetPlan is a pure function -- no landlock_* syscalls -- so
// these tests assert contract consumption (NoNetproxyFallbackPorts,
// resolved OAuth bind ports, named Unsupported reasons) without ever
// calling landlock_restrict_self (irreversible).

// TestBuildLandlockNetPlan_NetproxyMode verifies that with netproxy enabled
// (netproxyPort > 0) on ABI v4+, CONNECT is restricted to exactly the
// netproxy port and BIND is restricted to exactly the resolved OAuth ports.
func TestBuildLandlockNetPlan_NetproxyMode(t *testing.T) {
	oauthPorts := []int{52819, 3118}
	plan := buildLandlockNetPlan(4, netproxyDefaultPort, oauthPorts)

	if !plan.Handled {
		t.Fatal("expected Handled=true on ABI v4 with netproxyPort>0")
	}
	if !plan.HandleBindTCP {
		t.Error("expected HandleBindTCP=true in netproxy mode")
	}
	if len(plan.ConnectPorts) != 1 || plan.ConnectPorts[0] != netproxyDefaultPort {
		t.Errorf("ConnectPorts = %v, want [%d]", plan.ConnectPorts, netproxyDefaultPort)
	}
	if len(plan.BindPorts) != len(oauthPorts) {
		t.Errorf("BindPorts = %v, want %v", plan.BindPorts, oauthPorts)
	}
}

// TestBuildLandlockNetPlan_NoNetproxyFallback is the FIX4 regression test:
// --no-netproxy (netproxyPort<=0) on ABI v4+ must restrict CONNECT to
// exactly the shared contract's NoNetproxyFallbackPorts(), and must NOT
// handle BIND at all (HandleBindTCP=false) -- this is Linux's prior
// "unrestricted" behavior, now tightened to a named, contract-driven
// fallback instead of a silent no-op.
func TestBuildLandlockNetPlan_NoNetproxyFallback(t *testing.T) {
	plan := buildLandlockNetPlan(4, 0, nil)

	if !plan.Handled {
		t.Fatal("expected Handled=true on ABI v4 even with netproxyPort<=0 (fallback mode)")
	}
	if plan.HandleBindTCP {
		t.Error("expected HandleBindTCP=false in --no-netproxy fallback mode (must not regress dynamic OAuth binds)")
	}
	if len(plan.BindPorts) != 0 {
		t.Errorf("expected no BindPorts in fallback mode, got %v", plan.BindPorts)
	}
	want := NoNetproxyFallbackPorts()
	if len(plan.ConnectPorts) != len(want) {
		t.Fatalf("ConnectPorts = %v, want %v (contract NoNetproxyFallbackPorts)", plan.ConnectPorts, want)
	}
	for i, p := range want {
		if plan.ConnectPorts[i] != p {
			t.Errorf("ConnectPorts[%d] = %d, want %d", i, plan.ConnectPorts[i], p)
		}
	}
}

// TestBuildLandlockNetPlan_OldKernel verifies that on ABI < 4 (kernel < 6.7,
// no Landlock network rights at all), the plan handles nothing -- matching
// the pre-existing FS-only Landlock behavior on older kernels.
func TestBuildLandlockNetPlan_OldKernel(t *testing.T) {
	plan := buildLandlockNetPlan(3, netproxyDefaultPort, []int{1234})
	if plan.Handled {
		t.Error("expected Handled=false on ABI<4")
	}
	if len(plan.ConnectPorts) != 0 || len(plan.BindPorts) != 0 {
		t.Errorf("expected no ports handled on ABI<4, got connect=%v bind=%v", plan.ConnectPorts, plan.BindPorts)
	}

	planFallback := buildLandlockNetPlan(3, 0, nil)
	if planFallback.Handled {
		t.Error("expected Handled=false on ABI<4 in fallback mode too")
	}
}

// TestBuildLandlockNetPlan_NamesUnsupportedCapabilities is the Linux half of
// FIX4's capability/parity test: buildLandlockNetPlan must always name both
// CapFilenamePatternDeny and CapLoopbackScopedBind as Unsupported,
// regardless of ABI or netproxy mode -- Landlock has neither primitive on
// any kernel version. No silent drop: every backend either honors a
// contract capability or names it.
func TestBuildLandlockNetPlan_NamesUnsupportedCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name         string
		abi          int
		netproxyPort int
	}{
		{"abi4-netproxy", 4, netproxyDefaultPort},
		{"abi4-fallback", 4, 0},
		{"abi3-old-kernel", 3, netproxyDefaultPort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := buildLandlockNetPlan(tc.abi, tc.netproxyPort, nil)
			if _, ok := plan.Unsupported[CapFilenamePatternDeny]; !ok {
				t.Error("plan must name CapFilenamePatternDeny as Unsupported")
			}
			if _, ok := plan.Unsupported[CapLoopbackScopedBind]; !ok {
				t.Error("plan must name CapLoopbackScopedBind as Unsupported")
			}
		})
	}
}

// TestBuildLandlockNetPlan_ConnectPortsDoNotIncludeFallbackInNetproxyMode
// guards against a regression where the fallback ports (80/443) leak into
// netproxy mode's ConnectPorts -- in netproxy mode, ONLY the netproxy port
// may be connect-restricted-to; 80/443 direct egress must stay denied so
// all traffic is forced through the proxy.
func TestBuildLandlockNetPlan_ConnectPortsDoNotIncludeFallbackInNetproxyMode(t *testing.T) {
	plan := buildLandlockNetPlan(4, netproxyDefaultPort, nil)
	for _, p := range plan.ConnectPorts {
		if p == 80 || p == 443 {
			t.Errorf("netproxy-mode ConnectPorts must not include fallback ports 80/443 (found %d) -- these would bypass the proxy", p)
		}
	}
}
