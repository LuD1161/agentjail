package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
)

func TestRunMCPToolDiscoverJSON(t *testing.T) {
	var gotToken string
	var gotTimeout time.Duration
	dependencies := mcpToolDiscoveryDependencies{
		loadToken: func() (string, error) { return "control-secret", nil },
		discover: func(_ string, token string, timeout time.Duration) (grantctl.MCPToolsDiscoveryV1, error) {
			gotToken = token
			gotTimeout = timeout
			return grantctl.MCPToolsDiscoveryV1{
				ProtocolVersion: grantctl.MCPDiscoveryProtocolVersion,
				Servers: []grantctl.MCPServerToolsDiscoveryV1{{
					Server: "linear", Status: grantctl.MCPDiscoveryConnected, Tools: []string{"get_issue", "list_issues"},
				}},
			}, nil
		},
	}
	var out, errOut bytes.Buffer
	if code := runMCPToolDiscoverOutput([]string{"--json"}, &out, &errOut, dependencies); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	if gotToken != "control-secret" || gotTimeout != mcpToolDiscoveryTimeout {
		t.Fatalf("authority forwarding = %q/%s", gotToken, gotTimeout)
	}
	var got grantctl.MCPToolsDiscoveryV1
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(got.Servers) != 1 || len(got.Servers[0].Tools) != 2 || got.Servers[0].Tools[0] != "get_issue" {
		t.Fatalf("unexpected discovery: %#v", got)
	}
	if strings.Contains(out.String(), "control-secret") {
		t.Fatal("control token leaked to JSON output")
	}
}

func TestRunMCPToolDiscoverRedactsFailures(t *testing.T) {
	secret := "secret-from-config"
	dependencies := mcpToolDiscoveryDependencies{
		loadToken: func() (string, error) { return "control-secret", nil },
		discover: func(string, string, time.Duration) (grantctl.MCPToolsDiscoveryV1, error) {
			return grantctl.MCPToolsDiscoveryV1{}, errors.New(secret)
		},
	}
	var out, errOut bytes.Buffer
	if code := runMCPToolDiscoverOutput([]string{"--json"}, &out, &errOut, dependencies); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if strings.Contains(errOut.String(), secret) || strings.Contains(errOut.String(), "control-secret") {
		t.Fatalf("secret leaked to stderr: %q", errOut.String())
	}
}

func TestRunMCPToolDiscoverRejectsUnknownArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMCPToolDiscoverOutput([]string{"--launch-everything"}, &out, &errOut, mcpToolDiscoveryDependencies{}); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
