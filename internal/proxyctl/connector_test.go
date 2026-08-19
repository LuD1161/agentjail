package proxyctl

import "testing"

func TestConnectorAuthorityRejectsNonConnectorInput(t *testing.T) {
	for _, id := range []string{"chrome-cdp", "agent-selected-host", "x1"} {
		got, ok := ConnectorAuthority(id)
		if !ok || got != id+ConnectorAuthoritySuffix {
			t.Fatalf("ConnectorAuthority(%q) = %q, %t", id, got, ok)
		}
	}
	for _, id := range []string{"", "chrome.cdp", "host:9225", "../host", "UPPER"} {
		if got, ok := ConnectorAuthority(id); ok || got != "" {
			t.Fatalf("ConnectorAuthority(%q) = %q, %t; want refusal", id, got, ok)
		}
	}
}
