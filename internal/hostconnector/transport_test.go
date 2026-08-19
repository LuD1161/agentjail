package hostconnector

import "testing"

func TestTransportCapabilitiesNameEveryIsolationBoundary(t *testing.T) {
	want := map[Isolation]bool{
		IsolationSameHost:       false,
		IsolationLinuxContainer: false,
		IsolationMicroVM:        false,
		IsolationMacOSSandbox:   false,
		IsolationMacOSGuest:     false,
	}
	for _, report := range TransportCapabilities() {
		if _, ok := want[report.Isolation]; !ok {
			t.Fatalf("unexpected isolation report %q", report.Isolation)
		}
		if report.State != StateAvailable && report.State != StateUnavailable {
			t.Fatalf("invalid state for %q: %q", report.Isolation, report.State)
		}
		if report.Detail == "" {
			t.Fatalf("missing detail for %q", report.Isolation)
		}
		want[report.Isolation] = true
	}
	for isolation, reported := range want {
		if !reported {
			t.Fatalf("missing capability report for %q", isolation)
		}
	}
}

func TestMicroVMTransportFailsClosedWithoutLaunchPrimitive(t *testing.T) {
	report := TransportCapabilityFor(IsolationMicroVM)
	if report.State != StateUnavailable {
		t.Fatalf("microVM report = %#v, want unavailable", report)
	}
}
