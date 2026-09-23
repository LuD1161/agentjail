package daemonapp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/policyeval"
)

func TestResponseStillProducesRedactedLog(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	srv := &server{evaluator: benchmarkEvaluator{}}
	client, peer := net.Pipe()
	defer client.Close()
	srv.wg.Add(1)
	go srv.handleConn(context.Background(), peer)
	req := policyeval.Request{ID: "redaction", HookEvent: "PreToolUse", ToolName: "Write", ToolInput: map[string]interface{}{"content": "ordinary content", "password": "test-only-sensitive-value"}}
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp policyeval.Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	client.Close()
	srv.wg.Wait()
	if resp.Action != "allow" {
		t.Fatalf("response: %+v", resp)
	}
	output := logs.String()
	if strings.Contains(output, "test-only-sensitive-value") {
		t.Fatal("log contains sensitive value")
	}
	if !strings.Contains(output, "[redacted]") || !strings.Contains(output, "ordinary content") {
		t.Fatalf("expected redacted input in log: %s", output)
	}
}
