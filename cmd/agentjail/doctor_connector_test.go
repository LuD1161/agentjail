package main

import (
	"strings"
	"testing"
)

func TestConnectorDoctorDistinguishesGrantActivationTransportAndUpstream(t *testing.T) {
	checks := checkConnectorTransport()
	want := map[string]bool{
		"Runtime grant":                        false,
		"Connector authorization":              false,
		"Connector activation":                 false,
		"Connector upstream":                   false,
		"Connector transport: same_host":       false,
		"Connector transport: linux_container": false,
		"Connector transport: microvm":         false,
	}
	for _, check := range checks {
		if _, ok := want[check.label]; ok {
			want[check.label] = true
		}
	}
	for label, found := range want {
		if !found {
			t.Fatalf("doctor omitted %q: %#v", label, checks)
		}
	}
}

func TestRuntimeGrantDoctorDiagnosticsAreDistinctAndValueFree(t *testing.T) {
	cases := map[runtimeGrantDiagnostic]checkStatus{
		grantDiagnosticPolicyDenied: statusWarn, grantDiagnosticApprovalUnavailable: statusWarn,
		grantDiagnosticApprovalPending: statusWarn, grantDiagnosticApprovalDenied: statusWarn,
		grantDiagnosticInactive: statusWarn, grantDiagnosticExpired: statusWarn,
		grantDiagnosticRevoked: statusWarn, grantDiagnosticTransportUnavailable: statusWarn,
		grantDiagnosticActivationFailed: statusWarn, grantDiagnosticUpstreamUnreachable: statusWarn,
		grantDiagnosticActive: statusOK,
	}
	for state, want := range cases {
		check := runtimeGrantDiagnosticCheck(state)
		if check.status != want || check.detail == "" {
			t.Fatalf("%q = %#v, want status %q", state, check, want)
		}
		for _, forbidden := range []string{"127.0.0.1", "token", "secret", "destination"} {
			if strings.Contains(strings.ToLower(check.detail), forbidden) {
				t.Fatalf("%q leaked %q in %#v", state, forbidden, check)
			}
		}
	}
}
