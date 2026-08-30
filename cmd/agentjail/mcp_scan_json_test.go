package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/mcpclient"
)

func TestRenderMCPScanJSONRedactsConfigurationSecrets(t *testing.T) {
	const secret = "credential-must-not-appear"
	result := &mcpclient.ScanResult{Configured: []mcpclient.MCPServerEntry{{
		Name: "fixture", Package: "/private/bin/fixture",
		Config: mcpclient.MCPServerConfig{
			Name: "fixture", Type: "stdio", Command: "/private/bin/npx",
			Args: []string{"--token", secret}, Env: map[string]string{"TOKEN": secret},
			URL:     "https://user:" + secret + "@example.com/mcp?token=" + secret + "#" + secret,
			Headers: map[string]string{"Authorization": "Bearer " + secret},
		},
	}}}
	var out bytes.Buffer
	if code := renderMCPScanJSON(&out, &bytes.Buffer{}, result); code != 0 {
		t.Fatalf("renderMCPScanJSON returned %d", code)
	}
	text := out.String()
	if strings.Contains(text, secret) || strings.Contains(text, "/private/bin") {
		t.Fatalf("JSON retained secret or private path: %s", text)
	}
	if count := strings.Count(text, "[REDACTED]"); count < 4 {
		t.Fatalf("JSON redaction count = %d, output: %s", count, text)
	}
	if !strings.Contains(text, "https://example.com/mcp") {
		t.Fatalf("JSON removed safe endpoint metadata: %s", text)
	}
}
