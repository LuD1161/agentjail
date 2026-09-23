package daemonapp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/policyeval"
)

type benchmarkEvaluator struct{}

func (benchmarkEvaluator) Eval(_ context.Context, req policyeval.Request) (policyeval.Response, error) {
	return policyeval.Response{ID: req.ID, Action: "allow"}, nil
}
func (benchmarkEvaluator) Reload(context.Context, [][2]string, *agentconfig.PolicyConfig) error {
	return nil
}

func BenchmarkHookConnection(b *testing.B) {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(old) })
	for _, tc := range []struct {
		name string
		size int
	}{{"small", 32}, {"large", 512 * 1024}} {
		b.Run(tc.name, func(b *testing.B) {
			req := policyeval.Request{ID: "bench", ToolName: "Write", HookEvent: "PreToolUse", ToolInput: map[string]interface{}{"content": strings.Repeat("x", tc.size)}}
			srv := &server{evaluator: benchmarkEvaluator{}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				client, peer := net.Pipe()
				srv.wg.Add(1)
				go srv.handleConn(context.Background(), peer)
				if err := json.NewEncoder(client).Encode(req); err != nil {
					b.Fatal(err)
				}
				var resp policyeval.Response
				if err := json.NewDecoder(client).Decode(&resp); err != nil {
					b.Fatal(err)
				}
				client.Close()
				srv.wg.Wait()
			}
		})
	}
}
