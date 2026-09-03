package costanalytics

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCodexParserStateResumesCumulativeUsageAcrossModelChange(t *testing.T) {
	fallback := time.Date(2026, 8, 3, 18, 0, 0, 0, time.UTC)
	state := NewCodexParserState("rollout-file", fallback)
	records := []string{
		`{"timestamp":"2026-08-03T17:00:00Z","type":"session_meta","payload":{"id":"session-resume","forked_from_id":"parent","cwd":"/work/project"}}`,
		`{"type":"turn_context","payload":{"model":"gpt-5.6-luna"}}`,
		`{"timestamp":"2026-08-03T17:01:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":10},"last_token_usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":10}}}}`,
	}
	var first CodexUsageEvent
	for _, record := range records {
		if event, ok := ApplyCodexRecord(&state, []byte(record)); ok {
			first = event
		}
	}
	if first.Model != "gpt-5.6-luna" || first.Delta.InputTokens != 100 || first.Usage.Input != 80 {
		t.Fatalf("first event = %+v", first)
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var resumed CodexParserState
	if err := json.Unmarshal(encoded, &resumed); err != nil {
		t.Fatal(err)
	}
	if _, ok := ApplyCodexRecord(&resumed, []byte(`{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}`)); ok {
		t.Fatal("turn context produced usage")
	}
	second, ok := ApplyCodexRecord(&resumed, []byte(`{"timestamp":"2026-08-03T17:02:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":400,"cached_input_tokens":120,"output_tokens":30},"last_token_usage":{"input_tokens":300,"cached_input_tokens":100,"output_tokens":20}}}}`))
	if !ok {
		t.Fatal("appended cumulative usage was not decoded")
	}
	if second.SessionID != "session-resume" || second.Project != "/work/project" || second.Model != "gpt-5.6-sol" {
		t.Fatalf("second identity = %+v", second.TranscriptUsage)
	}
	if second.Delta.InputTokens != 300 || second.Delta.CachedInputTokens != 100 || second.Delta.OutputTokens != 20 {
		t.Fatalf("second delta = %+v", second.Delta)
	}
	if second.Usage.Input != 200 || second.Usage.CacheRead != 100 || second.Usage.Output != 20 {
		t.Fatalf("second pricing usage = %+v", second.Usage)
	}
	if second.Last == nil || second.Last.InputTokens != 300 || resumed.MaxTotal != 430 || resumed.ForkedFrom != "parent" {
		t.Fatalf("resumed state = %+v last=%+v", resumed, second.Last)
	}
}

func TestCodexParserStatePersistsUnsplitCumulativeBaseline(t *testing.T) {
	state := NewCodexParserState("session", time.Time{})
	if event, ok := ApplyCodexRecord(&state, []byte(`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":40,"output_tokens":5}}}}`)); ok {
		t.Fatalf("usage without a model produced split event: %+v", event)
	}
	if state.CanSplit || state.MaxTotal != 45 || state.Usage.InputTokens != 40 {
		t.Fatalf("state = %+v, want unsplit cumulative fallback", state)
	}
}

func TestCodexReaderUsesFinalCumulativeUsage(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "2026/07/31/rollout-one.jsonl", `
{"timestamp":"2026-07-31T17:00:00Z","type":"session_meta","payload":{"id":"session-1","cwd":"/work/agentjail","cli_version":"0.146.0","source":"cli"}}
{"timestamp":"2026-07-31T17:00:01Z","type":"turn_context","payload":{"model":"gpt-5.4"}}
{"timestamp":"2026-07-31T17:00:02Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":10,"output_tokens":30,"reasoning_output_tokens":5,"total_tokens":130},"last_token_usage":{"input_tokens":100,"output_tokens":30}}}}
{"timestamp":"2026-07-31T17:00:03Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":250,"cached_input_tokens":80,"cache_write_input_tokens":20,"output_tokens":70,"reasoning_output_tokens":15,"total_tokens":320},"last_token_usage":{"input_tokens":150,"output_tokens":40}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	got := sessions[0]
	if got.SessionID != "session-1" || got.Agent != "codex" || got.Model != "gpt-5.4" || got.Project != "/work/agentjail" {
		t.Fatalf("unexpected metadata: %+v", got)
	}
	if got.InputTokens != 150 || got.CacheRead != 80 || got.CacheWrite != 20 || got.OutputTokens != 70 || got.Reasoning != 15 {
		t.Fatalf("unexpected usage: %+v", got)
	}
	wantStarted := time.Date(2026, 7, 31, 17, 0, 0, 0, time.UTC)
	if !got.StartedAt.Equal(wantStarted) {
		t.Fatalf("started at %v, want %v", got.StartedAt, wantStarted)
	}
}

func TestCodexReaderContinuesAfterOversizedContentRecord(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "rollout-large.jsonl", `
{"type":"session_meta","payload":{"id":"session-large","cwd":"/work/project"}}
{"type":"response_item","payload":{"type":"function_call_output","output":"`+
		strings.Repeat("x", maxTranscriptLineBytes)+`"}}
{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":40,"cached_input_tokens":10,"output_tokens":5,"total_tokens":45}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].InputTokens != 30 || sessions[0].OutputTokens != 5 {
		t.Fatalf("sessions = %+v, want usage after oversized content record", sessions)
	}
}

func TestCodexReaderPricesLongContextPerRequest(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "rollout-long.jsonl", `
{"timestamp":"2026-08-03T17:00:00Z","type":"session_meta","payload":{"id":"session-long","cwd":"/work/project"}}
{"timestamp":"2026-08-03T17:00:01Z","type":"turn_context","payload":{"model":"gpt-5.6-sol"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":200000,"cached_input_tokens":50000,"output_tokens":1000,"total_tokens":201000},"last_token_usage":{"input_tokens":200000,"cached_input_tokens":50000,"output_tokens":1000,"total_tokens":201000}}}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500000,"cached_input_tokens":250000,"output_tokens":2000,"total_tokens":502000},"last_token_usage":{"input_tokens":300000,"cached_input_tokens":200000,"output_tokens":1000,"total_tokens":301000}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	got := sessions[0]
	if got.PricingMode != PricingModeRequestAware || math.Abs(got.CostUSD-2.05) > 1e-9 {
		t.Fatalf("request-aware session = %+v, want cost 2.05", got)
	}
}

func TestCodexReaderSplitsUsageWhenModelChanges(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "rollout-model-change.jsonl", `
{"timestamp":"2026-08-03T17:00:00Z","type":"session_meta","payload":{"id":"session-model-change","cwd":"/work/project"}}
{"timestamp":"2026-07-01T17:00:00Z","type":"session_meta","payload":{"id":"embedded-parent","cwd":"/work/parent"}}
{"type":"turn_context","payload":{"model":"gpt-5.6-luna"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100000,"cached_input_tokens":20000,"output_tokens":1000,"total_tokens":101000},"last_token_usage":{"input_tokens":100000,"cached_input_tokens":20000,"output_tokens":1000,"total_tokens":101000}}}}
{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":400000,"cached_input_tokens":120000,"output_tokens":3000,"total_tokens":403000},"last_token_usage":{"input_tokens":300000,"cached_input_tokens":100000,"output_tokens":2000,"total_tokens":302000}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v, want one row per model", sessions)
	}
	if sessions[0].Model != "gpt-5.6-luna" || sessions[0].InputTokens != 80_000 || math.Abs(sessions[0].CostUSD-0.088) > 1e-9 {
		t.Fatalf("Luna usage = %+v", sessions[0])
	}
	if sessions[1].Model != "gpt-5.6-sol" || sessions[1].InputTokens != 200_000 || math.Abs(sessions[1].CostUSD-2.19) > 1e-9 {
		t.Fatalf("Sol usage = %+v", sessions[1])
	}
	if sessions[0].SessionID != sessions[1].SessionID || sessions[0].PricingMode != PricingModeRequestAware || sessions[1].PricingMode != PricingModeRequestAware {
		t.Fatalf("split session metadata = %+v", sessions)
	}
	if sessions[0].SessionID != "session-model-change" || sessions[0].Project != "/work/project" {
		t.Fatalf("embedded parent metadata replaced child identity: %+v", sessions[0])
	}
	if want := time.Date(2026, 8, 3, 17, 0, 0, 0, time.UTC); !sessions[0].StartedAt.Equal(want) {
		t.Fatalf("StartedAt = %v, want child start %v", sessions[0].StartedAt, want)
	}
}

func TestCodexReaderExcludesCopiedForkHistory(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "parent.jsonl", `
{"timestamp":"2026-08-03T16:00:00Z","type":"session_meta","payload":{"id":"parent","cwd":"/work/project"}}
{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100000,"output_tokens":1000},"last_token_usage":{"input_tokens":100000,"output_tokens":1000}}}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":200000,"output_tokens":2000},"last_token_usage":{"input_tokens":100000,"output_tokens":1000}}}}
`)
	writeCodexTranscript(t, root, "child.jsonl", `
{"timestamp":"2026-08-03T17:00:00Z","type":"session_meta","payload":{"id":"child","forked_from_id":"parent","cwd":"/work/project"}}
{"timestamp":"2026-08-03T17:00:00.001Z","type":"session_meta","payload":{"id":"parent","cwd":"/work/project"}}
{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100000,"output_tokens":1000},"last_token_usage":{"input_tokens":100000,"output_tokens":1000}}}}
{"type":"turn_context","payload":{"model":"gpt-5.6-luna"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":150000,"output_tokens":1500},"last_token_usage":{"input_tokens":50000,"output_tokens":500}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v, want parent plus child increment", sessions)
	}
	byID := make(map[SessionID]SessionCost, len(sessions))
	for _, session := range sessions {
		byID[session.SessionID] = session
	}
	if got := byID["parent"]; got.Model != "gpt-5.6-sol" || got.InputTokens != 200_000 || got.OutputTokens != 2_000 {
		t.Fatalf("parent usage = %+v", got)
	}
	if got := byID["child"]; got.Model != "gpt-5.6-luna" || got.InputTokens != 50_000 || got.OutputTokens != 500 {
		t.Fatalf("child incremental usage = %+v", got)
	}
}

func TestCodexReaderWarnsWhenForkParentIsUnavailable(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "child.jsonl", `
{"timestamp":"2026-08-03T17:00:00Z","type":"session_meta","payload":{"id":"child","forked_from_id":"missing-parent","cwd":"/work/project"}}
{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100000,"output_tokens":1000},"last_token_usage":{"input_tokens":100000,"output_tokens":1000}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if len(sessions) != 1 || err == nil || !strings.Contains(err.Error(), "fork parent") {
		t.Fatalf("sessions=%+v err=%v, want retained usage and fork warning", sessions, err)
	}
}

func TestCodexReaderIgnoresUnknownAndMalformedRecords(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "rollout.jsonl", `
not-json
{"timestamp":"2026-07-31T17:00:00Z","type":"session_meta","payload":{"session_id":"session-2","cwd":"/work/project"}}
{"type":"future_record","payload":{"conversation_text":"must not be decoded"}}
{"type":"event_msg","payload":{"type":"future_event","info":{"total_token_usage":{"total_tokens":99999}}}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":40,"cached_input_tokens":10,"output_tokens":5,"total_tokens":45}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].InputTokens != 30 || sessions[0].OutputTokens != 5 {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
}

func TestCodexReaderAcceptsLargeOpaqueRecordBeforeUsage(t *testing.T) {
	root := t.TempDir()
	large := `{"type":"response_item","payload":{"type":"message","content":"` + strings.Repeat("x", (1<<20)+1) + `"}}`
	writeCodexTranscript(t, root, "rollout-large.jsonl", large+`
{"timestamp":"2026-07-31T17:00:00Z","type":"session_meta","payload":{"id":"session-large","cwd":"/work/project"}}
{"type":"turn_context","payload":{"model":"gpt-5.4"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":40,"cached_input_tokens":10,"output_tokens":5,"total_tokens":45}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].InputTokens != 30 || sessions[0].OutputTokens != 5 {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
}

func TestCodexReaderDeduplicatesSessionAcrossFiles(t *testing.T) {
	root := t.TempDir()
	writeCodexTranscript(t, root, "old.jsonl", `
{"timestamp":"2026-07-31T16:00:00Z","type":"session_meta","payload":{"id":"same-session","cwd":"/old"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}}
`)
	writeCodexTranscript(t, root, "new.jsonl", `
{"timestamp":"2026-07-31T17:00:00Z","type":"session_meta","payload":{"id":"same-session","cwd":"/new"}}
{"timestamp":"2026-07-31T17:00:01Z","type":"turn_context","payload":{"model":"gpt-5.4-mini"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":30,"output_tokens":20,"total_tokens":50}}}}
`)

	sessions, err := NewCodexReaderAt(root).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	if sessions[0].InputTokens != 30 || sessions[0].OutputTokens != 20 || sessions[0].Model != "gpt-5.4-mini" || sessions[0].Project != "/new" {
		t.Fatalf("unexpected merged session: %+v", sessions[0])
	}
}

func TestCodexReaderMissingDirectoryAndSince(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none")
	sessions, err := NewCodexReaderAt(missing).ReadSessions(time.Time{})
	if err != nil || len(sessions) != 0 {
		t.Fatalf("missing directory: sessions=%+v err=%v", sessions, err)
	}

	root := t.TempDir()
	writeCodexTranscript(t, root, "old.jsonl", `
{"timestamp":"2026-07-30T17:00:00Z","type":"session_meta","payload":{"id":"old"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"total_tokens":10}}}}
`)
	since := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	sessions, err = NewCodexReaderAt(root).ReadSessions(since)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("since filter: sessions=%+v err=%v", sessions, err)
	}
}

func writeCodexTranscript(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
