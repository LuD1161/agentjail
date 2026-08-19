package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHostConnectorConfigurationForEnforcement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	content := "network:\n  host_connectors:\n    - id: chrome-cdp\n      transport: cdp\n      host: 127.0.0.1\n      port: 9225\n      path: /json/version\n      probe: chrome_cdp\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadPolicyForEnforcement(path)
	if err != nil {
		t.Fatalf("LoadPolicyForEnforcement() error = %v", err)
	}
	connectors, err := cfg.Network.ConfiguredHostConnectors()
	if err != nil || len(connectors) != 1 || connectors[0].ID() != "chrome-cdp" {
		t.Fatalf("ConfiguredHostConnectors() = %#v, %v", connectors, err)
	}
}

func TestHostConnectorConfigurationRejectsUnsafeDestinations(t *testing.T) {
	for _, content := range []string{
		"network:\n  host_connectors:\n    - id: cdp\n      transport: cdp\n      host: 0.0.0.0\n      port: 9225\n      path: /json/version\n      probe: chrome_cdp\n",
		"network:\n  host_connectors:\n    - id: cdp\n      transport: cdp\n      host: example.com\n      port: 9225\n      path: /json/version\n      probe: chrome_cdp\n",
		"network:\n  host_connectors:\n    - id: cdp\n      transport: cdp\n      host: 127.0.0.1\n      port: 9225\n      path: /json/version?secret=x\n      probe: chrome_cdp\n",
		"network:\n  host_connectors:\n    - id: cdp\n      transport: cdp\n      host: 127.0.0.1\n      port: 9225\n      path: /json/version\n      probe: reachable\n",
		"network:\n  host_connectors:\n    - id: cdp\n      transport: cdp\n      host: 127.0.0.1\n      port: 9225\n      path: /json/version\n      probe: chrome_cdp\n    - id: cdp\n      transport: cdp\n      host: 127.0.0.1\n      port: 9226\n      path: /json/version\n      probe: chrome_cdp\n",
	} {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicyForEnforcement(path); err == nil {
			t.Fatalf("LoadPolicyForEnforcement() succeeded for unsafe host connector:\n%s", content)
		}
	}
}

func TestProjectOverlayCannotAddHostConnector(t *testing.T) {
	base := Default()
	overlay := &PolicyConfig{Network: NetworkConfig{HostConnectors: []HostConnectorConfig{{ID: "cdp", Transport: "cdp", Host: "127.0.0.1", Port: 9225, Path: "/json/version", Probe: "chrome_cdp"}}}}
	if got := MergeProjectOverlay(base, overlay).Network.HostConnectors; len(got) != 0 {
		t.Fatalf("project overlay added host connector: %#v", got)
	}
}
