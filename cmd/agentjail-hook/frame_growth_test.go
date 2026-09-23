package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/wire"
)

func TestHookFrameBufferGrowsForLargeResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	reason := strings.Repeat("x", 900*1024)
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		var req daemonRequest
		if err := json.NewDecoder(server).Decode(&req); err != nil {
			done <- err
			return
		}
		done <- json.NewEncoder(server).Encode(daemonResponse{Action: "allow", Reason: reason})
	}()
	resp, err := sendAndReceive(client, daemonRequest{Agent: "codex", Capabilities: []string{wire.CapabilityCodexApprovalBridgeV1}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reason != reason {
		t.Fatal("large response changed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
