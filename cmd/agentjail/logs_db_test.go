package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

func newTestDB(t *testing.T) (string, store.EventStore) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agentjail.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	records := []store.DecisionRecord{
		{
			Ts:        time.Now().Add(-2 * time.Minute).UTC(),
			SessionID: "sess-alpha",
			Agent:     "claude",
			ToolName:  "Bash",
			Summary:   "aws s3 ls",
			Action:    "allow",
			RuleID:    "command_policy/default-allow",
			ElapsedUs: 120,
			CWD:       "/home/dev/project",
		},
		{
			Ts:        time.Now().Add(-1 * time.Minute).UTC(),
			SessionID: "sess-alpha",
			Agent:     "claude",
			ToolName:  "Bash",
			Summary:   "aws s3 rb --force prod-bucket",
			Action:    "deny",
			RuleID:    "library/no-aws-destructive",
			Reason:    "destructive S3 operation",
			ElapsedUs: 3400,
			CWD:       "/home/dev/project",
		},
		{
			Ts:        time.Now().Add(-30 * time.Second).UTC(),
			SessionID: "sess-beta",
			Agent:     "codex",
			ToolName:  "Write",
			Summary:   "/tmp/output.txt",
			Action:    "allow",
			RuleID:    "file_policy/project_allow",
			ElapsedUs: 88,
			CWD:       "/home/dev/repo",
		},
	}
	for _, r := range records {
		if err := st.RecordDecision(ctx, r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	return dbPath, st
}

func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureStderr: pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	f()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("captureStderr: read: %v", err)
	}
	return buf.String()
}

func TestLogsDB_NoFollow(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runLogs([]string{"--db", dbPath, "--no-follow", "--no-color", "--basic"})
		if code != 0 {
			t.Errorf("runLogs exit = %d, want 0", code)
		}
	})
	outLower := strings.ToLower(out)
	if !strings.Contains(outLower, "allow") {
		t.Errorf("output missing allow action: %q", out)
	}
	if !strings.Contains(outLower, "deny") {
		t.Errorf("output missing deny action: %q", out)
	}
	if !strings.Contains(out, "Bash") {
		t.Errorf("output missing Bash tool: %q", out)
	}
	if !strings.Contains(out, "Write") {
		t.Errorf("output missing Write tool: %q", out)
	}
	if !strings.Contains(out, "Claude") {
		t.Errorf("output missing Claude agent: %q", out)
	}
}

func TestLogsDB_VerboseShowsSummary(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runLogs([]string{"--db", dbPath, "--no-follow", "--no-color", "--basic", "-v"})
		if code != 0 {
			t.Errorf("runLogs exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "aws s3 ls") {
		t.Errorf("verbose output missing first summary: %q", out)
	}
	if !strings.Contains(out, "aws s3 rb --force prod-bucket") {
		t.Errorf("verbose output missing second summary: %q", out)
	}
}

func TestLogsDB_ActionFilter(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runLogs([]string{"--db", dbPath, "--no-follow", "--no-color", "--basic", "--action", "deny"})
		if code != 0 {
			t.Errorf("runLogs exit = %d, want 0", code)
		}
	})
	outLower := strings.ToLower(out)
	if !strings.Contains(outLower, "deny") {
		t.Errorf("filtered output missing deny: %q", out)
	}
	if strings.Contains(outLower, "allow") {
		t.Errorf("filtered output should not contain allow: %q", out)
	}
}

func TestLogsDB_ToolFilter(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runLogs([]string{"--db", dbPath, "--no-follow", "--no-color", "--basic", "--tool", "Write"})
		if code != 0 {
			t.Errorf("runLogs exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "Write") {
		t.Errorf("tool-filtered output missing Write tool: %q", out)
	}
	if strings.Contains(out, "Bash") {
		t.Errorf("tool-filtered output should not contain Bash: %q", out)
	}
}

func TestLogsDB_JSONOutput(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runLogs([]string{"--db", dbPath, "--no-follow", "--no-color", "--basic", "--json"})
		if code != 0 {
			t.Errorf("runLogs exit = %d, want 0", code)
		}
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 JSON lines, got %d: %q", len(lines), out)
	}
	for i, line := range lines {
		if !strings.Contains(line, `"msg":"eval"`) {
			t.Errorf("line %d is not an eval JSON line: %q", i, line)
		}
		if !strings.Contains(line, `"action"`) {
			t.Errorf("line %d missing action field: %q", i, line)
		}
	}
}

func TestLogsDB_LatestSelectsNewestAndPrintsChronologically(t *testing.T) {
	dbPath, st := newTestDB(t)
	ctx := context.Background()
	for _, summary := range []string{"fourth", "fifth", "sixth"} {
		if err := st.RecordDecision(ctx, store.DecisionRecord{
			Ts:        time.Now().UTC(),
			SessionID: "sess-latest",
			Agent:     "codex",
			ToolName:  "Bash",
			Summary:   summary,
			Action:    "allow",
		}); err != nil {
			t.Fatalf("RecordDecision(%s): %v", summary, err)
		}
	}

	out := captureStdout(t, func() {
		code := runLogs([]string{"--db", dbPath, "--latest", "2", "--json", "--no-color", "--basic"})
		if code != 0 {
			t.Errorf("runLogs exit = %d, want 0", code)
		}
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d rows, want 2: %q", len(lines), out)
	}
	var got []evalLine
	for _, line := range lines {
		var row evalLine
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("decode JSON line %q: %v", line, err)
		}
		got = append(got, row)
	}
	if got[0].Summary != "fifth" || got[1].Summary != "sixth" {
		t.Fatalf("latest rows = [%q, %q], want [fifth, sixth]", got[0].Summary, got[1].Summary)
	}
}

func TestLogsDB_NoFollowTraversesEveryPage(t *testing.T) {
	dbPath, st := newTestDB(t)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if err := st.RecordDecision(ctx, store.DecisionRecord{
			Ts:        time.Now().UTC(),
			SessionID: "sess-pages",
			Agent:     "codex",
			ToolName:  "Bash",
			Summary:   fmt.Sprintf("paged-%03d", i),
			Action:    "allow",
		}); err != nil {
			t.Fatalf("RecordDecision(%d): %v", i, err)
		}
	}

	out := captureStdout(t, func() {
		code := streamStoredLogsWithPageSize(logsOpts{
			dbPath: dbPath,
			raw:    true,
			basic:  true,
		}, make(chan struct{}), 100)
		if code != 0 {
			t.Errorf("streamStoredLogsWithPageSize exit = %d, want 0", code)
		}
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 103 {
		t.Fatalf("got %d rows, want 103", len(lines))
	}
	if !strings.Contains(lines[len(lines)-1], `"summary":"paged-099"`) {
		t.Fatalf("last row is not the last stored decision: %q", lines[len(lines)-1])
	}
}

func TestLogsDB_LatestRejectsInvalidLimit(t *testing.T) {
	for _, limit := range []string{"0", "10001"} {
		code := 0
		captureStderr(t, func() {
			code = runLogs([]string{"--latest", limit})
		})
		if code != 2 {
			t.Errorf("--latest %s exit = %d, want 2", limit, code)
		}
	}
}

func TestLogsDB_MissingDB(t *testing.T) {
	missingDB := filepath.Join(t.TempDir(), "nonexistent.db")
	missingLog := filepath.Join(t.TempDir(), "nonexistent.log")
	code := 0
	captureStderr(t, func() {
		code = runLogs([]string{"--db", missingDB, "--log", missingLog, "--no-follow", "--no-color", "--basic"})
	})
	if code == 0 {
		t.Errorf("runLogs with missing DB and missing log should return non-zero, got 0")
	}
}

func TestReplayList(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runReplay([]string{"--db", dbPath, "--list"})
		if code != 0 {
			t.Errorf("runReplay --list exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "SESSION") {
		t.Errorf("output missing SESSION header: %q", out)
	}
	if !strings.Contains(out, "sess-alp") {
		t.Errorf("output missing sess-alp (truncated sess-alpha): %q", out)
	}
	if !strings.Contains(out, "sess-bet") {
		t.Errorf("output missing sess-bet (truncated sess-beta): %q", out)
	}
}

func TestReplaySession(t *testing.T) {
	dbPath, _ := newTestDB(t)
	out := captureStdout(t, func() {
		code := runReplay([]string{"--db", dbPath, "--session", "sess-alpha"})
		if code != 0 {
			t.Errorf("runReplay --session exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "aws s3 ls") {
		t.Errorf("replay output missing first decision: %q", out)
	}
	if !strings.Contains(out, "aws s3 rb --force prod-bucket") {
		t.Errorf("replay output missing second decision: %q", out)
	}
	if !strings.Contains(out, "destructive S3 operation") {
		t.Errorf("replay output missing reason: %q", out)
	}
}

func TestReplaySessionVerbose(t *testing.T) {
	dbPath, st := newTestDB(t)
	ctx := context.Background()
	if err := st.RecordDecision(ctx, store.DecisionRecord{
		Ts:        time.Now().UTC(),
		SessionID: "sess-verbose",
		Agent:     "claude",
		ToolName:  "Bash",
		Summary:   "aws iam create-user",
		Action:    "ask",
		RuleID:    "aws_policy/create_ask",
		Reason:    "creating IAM user requires confirmation",
		ElapsedUs: 500,
		CWD:       "/home/dev",
		ToolInput: map[string]interface{}{
			"command":               "aws iam create-user --user-name test",
			"AWS_SECRET_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
		},
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	out := captureStdout(t, func() {
		code := runReplay([]string{"--db", dbPath, "--session", "sess-verbose", "--verbose"})
		if code != 0 {
			t.Errorf("runReplay --verbose exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "tool_input:") {
		t.Errorf("verbose output missing tool_input line: %q", out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("verbose output leaked secret value: %q", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("verbose output missing [redacted] marker: %q", out)
	}
}

func TestReplayMissingDB(t *testing.T) {
	uncreatablePath := "/dev/null/cannot-create/db.sqlite"
	code := 0
	captureStderr(t, func() {
		code = runReplay([]string{"--db", uncreatablePath, "--list"})
	})
	if code == 0 {
		t.Errorf("runReplay with uncreatable DB path should return non-zero, got 0")
	}
}

func TestReplayNoSessionArg(t *testing.T) {
	dbPath, _ := newTestDB(t)
	code := 0
	stderr := captureStderr(t, func() {
		code = runReplay([]string{"--db", dbPath})
	})
	if code != 2 {
		t.Errorf("runReplay without --session or --list should exit 2, got %d", code)
	}
	if !strings.Contains(stderr, "--session is required") {
		t.Errorf("stderr should mention --session requirement: %q", stderr)
	}
}
