package shieldapp

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/hostconnector"
)

func TestShieldUsesSharedConnectorTransportReport(t *testing.T) {
	got := connectorTransportCapabilities()
	if len(got) == 0 {
		t.Fatal("shield has no connector transport report")
	}
	found := false
	for _, report := range got {
		if report.Isolation == hostconnector.IsolationMicroVM {
			found = true
			if report.State != hostconnector.StateUnavailable {
				t.Fatalf("microVM transport report = %#v, want fail-closed", report)
			}
		}
	}
	if !found {
		t.Fatal("shield report omitted microVM transport")
	}
}
