package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
)

func TestInstallDaemonRunsMCPDiscoveryOnlyAfterPreamble(t *testing.T) {
	var order []string
	dependencies := daemonMCPInstallDependencies{
		preamble: func(string, io.Writer, []string) error {
			order = append(order, "preamble")
			return nil
		},
		discover: func(io.Writer, installMCPDiscoveryDependencies) {
			order = append(order, "discover")
		},
	}
	if err := installDaemonWithMCPDiscoveryDependencies("/tmp/home", io.Discard, nil, dependencies); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "preamble,discover" {
		t.Fatalf("install order = %q", got)
	}

	order = nil
	dependencies.preamble = func(string, io.Writer, []string) error { return errors.New("failed") }
	if err := installDaemonWithMCPDiscoveryDependencies("/tmp/home", io.Discard, nil, dependencies); err == nil {
		t.Fatal("failed preamble was accepted")
	}
	if len(order) != 0 {
		t.Fatalf("discovery ran after failed preamble: %v", order)
	}
}

func TestInstallMCPDiscoveryCatalogsToolsAndReportsBoundedStatuses(t *testing.T) {
	var out bytes.Buffer
	dependencies := installMCPDiscoveryDependencies{
		loadToken:   func() (string, error) { return "control-secret", nil },
		socketReady: func(string) bool { return true },
		wait:        func(time.Duration) {},
		attempts:    1,
		discover: func(_ string, token string, timeout time.Duration) (grantctl.MCPToolsDiscoveryV1, error) {
			if token != "control-secret" || timeout != mcpToolDiscoveryTimeout {
				t.Fatalf("authority = %q/%s", token, timeout)
			}
			return grantctl.MCPToolsDiscoveryV1{
				ProtocolVersion: grantctl.MCPDiscoveryProtocolVersion,
				Servers: []grantctl.MCPServerToolsDiscoveryV1{
					{Server: "linear", Status: grantctl.MCPDiscoveryConnected, Tools: []string{"get_issue", "list_issues"}},
					{Server: "memory", Status: grantctl.MCPDiscoveryAuthRequired, Tools: []string{}},
				},
			}, nil
		},
	}
	runInstallMCPDiscovery(&out, dependencies)
	got := out.String()
	for _, want := range []string{"Cataloging MCP tools", "2 tool(s) cataloged", "1 connected", "1 need authentication"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "control-secret") {
		t.Fatalf("control token leaked: %s", got)
	}
}

func TestInstallMCPDiscoveryFailureIsNonFatalAndRedacted(t *testing.T) {
	secret := "credential-from-config"
	var out bytes.Buffer
	runInstallMCPDiscovery(&out, installMCPDiscoveryDependencies{
		loadToken:   func() (string, error) { return "control-secret", nil },
		socketReady: func(string) bool { return true },
		wait:        func(time.Duration) {},
		attempts:    1,
		discover: func(string, string, time.Duration) (grantctl.MCPToolsDiscoveryV1, error) {
			return grantctl.MCPToolsDiscoveryV1{}, errors.New(secret)
		},
	})
	if got := out.String(); !strings.Contains(got, "could not complete") || strings.Contains(got, secret) || strings.Contains(got, "control-secret") {
		t.Fatalf("unsafe failure output: %q", got)
	}
}

func TestInstallMCPDiscoveryBoundsDaemonReadinessWait(t *testing.T) {
	secret := "token-loader-secret"
	waits := 0
	var out bytes.Buffer
	runInstallMCPDiscovery(&out, installMCPDiscoveryDependencies{
		loadToken:   func() (string, error) { return "", errors.New(secret) },
		socketReady: func(string) bool { t.Fatal("socket checked without authority"); return false },
		wait:        func(time.Duration) { waits++ },
		attempts:    3,
		discover: func(string, string, time.Duration) (grantctl.MCPToolsDiscoveryV1, error) {
			t.Fatal("discovery ran without authority")
			return grantctl.MCPToolsDiscoveryV1{}, nil
		},
	})
	if waits != 2 {
		t.Fatalf("readiness waits = %d, want 2", waits)
	}
	if got := out.String(); !strings.Contains(got, "authority is not ready") || strings.Contains(got, secret) {
		t.Fatalf("unsafe readiness output: %q", got)
	}
}
