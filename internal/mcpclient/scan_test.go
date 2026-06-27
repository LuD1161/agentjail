package mcpclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestScanSessionLogs verifies that ScanSessionLogs correctly discovers
// claude.ai remote connectors from Claude Code session JSONL files.
func TestScanSessionLogs(t *testing.T) {
	// Build a temp directory mimicking ~/.claude/projects/testproject/
	home := t.TempDir()
	projectDir := filepath.Join(home, ".claude", "projects", "testproject")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write a JSONL file with a deferred_tools_delta attachment entry.
	// Include both mcp__claude_ai_* tools and non-claude_ai tools.
	delta := map[string]any{
		"type": "attachment",
		"attachment": map[string]any{
			"type": "deferred_tools_delta",
			"addedNames": []string{
				"mcp__claude_ai_Gmail__authenticate",
				"mcp__claude_ai_Gmail__complete_authentication",
				"mcp__claude_ai_typefully__typefully_create_draft",
				"mcp__claude_ai_typefully__typefully_list_drafts",
				// Non-claude_ai entries -- must be excluded.
				"mcp__linear-server__get_issue",
				"mcp__filesystem__read_file",
			},
		},
	}

	deltaJSON, err := json.Marshal(delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}

	// Also add an unrelated line before the delta (should be skipped).
	sessionFile := filepath.Join(projectDir, "session1.jsonl")
	content := `{"type":"message","role":"user","content":"hello"}` + "\n" +
		string(deltaJSON) + "\n"

	if err := os.WriteFile(sessionFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	result := ScanSessionLogs(home)

	// AC1: function returns non-nil result with connectors.
	if result == nil {
		t.Fatal("ScanSessionLogs returned nil, expected connectors")
	}

	// AC2: Gmail connector is extracted with correct tools.
	gmailTools, ok := result["claude_ai_Gmail"]
	if !ok {
		t.Fatalf("expected server 'claude_ai_Gmail' in result, got keys: %v", serverKeys(result))
	}
	wantGmail := []string{"authenticate", "complete_authentication"}
	if !reflect.DeepEqual(gmailTools, wantGmail) {
		t.Errorf("claude_ai_Gmail tools = %v, want %v", gmailTools, wantGmail)
	}

	// AC2: typefully connector is extracted with correct tools.
	typefullyTools, ok := result["claude_ai_typefully"]
	if !ok {
		t.Fatalf("expected server 'claude_ai_typefully' in result, got keys: %v", serverKeys(result))
	}
	wantTypefully := []string{"typefully_create_draft", "typefully_list_drafts"}
	if !reflect.DeepEqual(typefullyTools, wantTypefully) {
		t.Errorf("claude_ai_typefully tools = %v, want %v", typefullyTools, wantTypefully)
	}

	// AC3: non-claude_ai tools are excluded.
	if _, ok := result["linear-server"]; ok {
		t.Error("expected 'linear-server' to be excluded (not mcp__claude_ai_*)")
	}
	if _, ok := result["filesystem"]; ok {
		t.Error("expected 'filesystem' to be excluded (not mcp__claude_ai_*)")
	}
}

// TestScanSessionLogs_Deduplication verifies that duplicate tool names across
// multiple JSONL files or repeated deltas are deduplicated.
func TestScanSessionLogs_Deduplication(t *testing.T) {
	home := t.TempDir()
	projectDir := filepath.Join(home, ".claude", "projects", "testproject")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Two session files, both mentioning the same tools.
	delta := map[string]any{
		"type": "attachment",
		"attachment": map[string]any{
			"type": "deferred_tools_delta",
			"addedNames": []string{
				"mcp__claude_ai_Gmail__authenticate",
				"mcp__claude_ai_Gmail__authenticate", // intentional duplicate
			},
		},
	}
	deltaJSON, _ := json.Marshal(delta)

	for _, name := range []string{"session1.jsonl", "session2.jsonl"} {
		f := filepath.Join(projectDir, name)
		if err := os.WriteFile(f, deltaJSON, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	result := ScanSessionLogs(home)
	if result == nil {
		t.Fatal("ScanSessionLogs returned nil")
	}

	gmailTools := result["claude_ai_Gmail"]
	// Should be deduplicated - only one "authenticate" entry.
	if len(gmailTools) != 1 || gmailTools[0] != "authenticate" {
		t.Errorf("expected deduplicated [authenticate], got %v", gmailTools)
	}
}

// TestScanSessionLogs_NoClaudeDir verifies graceful handling of missing dirs.
func TestScanSessionLogs_NoClaudeDir(t *testing.T) {
	home := t.TempDir()
	// No .claude/projects directory created.
	result := ScanSessionLogs(home)
	if result != nil {
		t.Errorf("expected nil for missing directory, got %v", result)
	}
}

// TestScanSessionLogs_SkipsNonDeltaEntries verifies that only
// deferred_tools_delta attachments are processed.
func TestScanSessionLogs_SkipsNonDeltaEntries(t *testing.T) {
	home := t.TempDir()
	projectDir := filepath.Join(home, ".claude", "projects", "testproject")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// A JSONL file with no deferred_tools_delta entry.
	content := `{"type":"message","role":"user"}` + "\n" +
		`{"type":"attachment","attachment":{"type":"other_type","addedNames":["mcp__claude_ai_Gmail__authenticate"]}}` + "\n"

	if err := os.WriteFile(filepath.Join(projectDir, "session.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result := ScanSessionLogs(home)
	if result != nil {
		t.Errorf("expected nil when no deferred_tools_delta present, got %v", result)
	}
}

// serverKeys returns sorted server names from a result map, for use in
// diagnostic messages.
func serverKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
