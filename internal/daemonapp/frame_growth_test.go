package daemonapp

import (
	"strings"
	"testing"
)

func TestDaemonFrameBufferGrowsForLargeToolInput(t *testing.T) {
	_, sock := newTestServer(t)
	resp := sendRequest(t, sock, Request{ID: "large-frame", HookEvent: "PreToolUse", ToolName: "Write", ToolInput: map[string]interface{}{"content": strings.Repeat("x", 900*1024)}})
	if resp.ID != "large-frame" || resp.Action != "allow" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
