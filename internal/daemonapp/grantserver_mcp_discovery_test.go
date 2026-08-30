package daemonapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
)

type stubMCPToolDiscoveryService struct {
	discovery grantctl.MCPToolsDiscoveryV1
	err       error
}

func (s stubMCPToolDiscoveryService) Discover(context.Context, time.Time) (grantctl.MCPToolsDiscoveryV1, error) {
	return s.discovery, s.err
}

func TestMCPToolsDiscoveryResponseIsExplicitVersionedAndGenericOnFailure(t *testing.T) {
	if response := mcpToolsDiscoveryResponse(nil, grantctl.MCPDiscoveryProtocolVersion, time.Now()); response.OK {
		t.Fatal("nil discovery service accepted")
	}
	if response := mcpToolsDiscoveryResponse(stubMCPToolDiscoveryService{}, 0, time.Now()); response.OK {
		t.Fatal("missing protocol version accepted")
	}
	want := grantctl.MCPToolsDiscoveryV1{
		ProtocolVersion: grantctl.MCPDiscoveryProtocolVersion,
		Servers: []grantctl.MCPServerToolsDiscoveryV1{{
			Server: "linear", Status: grantctl.MCPDiscoveryConnected, Tools: []string{"get_issue"},
		}},
	}
	response := mcpToolsDiscoveryResponse(stubMCPToolDiscoveryService{discovery: want}, grantctl.MCPDiscoveryProtocolVersion, time.Now())
	if !response.OK || response.MCPToolsDiscovery == nil || len(response.MCPToolsDiscovery.Servers) != 1 {
		t.Fatalf("successful discovery response: %+v", response)
	}
	response = mcpToolsDiscoveryResponse(stubMCPToolDiscoveryService{err: errors.New("secret-bearing detail")}, grantctl.MCPDiscoveryProtocolVersion, time.Now())
	if response.OK || response.Error != "MCP tool discovery failed" {
		t.Fatalf("failure was not bounded and generic: %+v", response)
	}
}
