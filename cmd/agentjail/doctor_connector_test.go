package main

import "testing"

func TestConnectorDoctorDistinguishesGrantActivationTransportAndUpstream(t *testing.T) {
	checks := checkConnectorTransport()
	want := map[string]bool{
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
