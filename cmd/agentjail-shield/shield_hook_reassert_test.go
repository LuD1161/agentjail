package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
)

// recordingEmitter captures emitted audit events for assertions, without
// touching a real store.
type recordingEmitter struct {
	events []audit.Event
}

func (r *recordingEmitter) Emit(_ context.Context, e audit.Event) error {
	r.events = append(r.events, e)
	return nil
}

// ---- agentForCommand ---------------------------------------------------------

func TestAgentForCommand_KnownAgents(t *testing.T) {
	cases := []struct {
		cmd    string
		wantID string
	}{
		{"claude", "claude-code"},
		{"/usr/local/bin/claude", "claude-code"},
		{"codex", "codex"},
		{"cursor", "cursor"},
		{"cursor-agent", "cursor"},
	}
	for _, c := range cases {
		agent, ok := agentForCommand(c.cmd)
		if !ok {
			t.Errorf("agentForCommand(%q) ok = false, want true", c.cmd)
			continue
		}
		if agent.ID() != c.wantID {
			t.Errorf("agentForCommand(%q).ID() = %q, want %q", c.cmd, agent.ID(), c.wantID)
		}
	}
}

// TestAgentForCommand_UnknownSkipsGracefully verifies that a command with no
// known hook-registration mechanism is skipped (ok=false) rather than
// guessed at.
func TestAgentForCommand_UnknownSkipsGracefully(t *testing.T) {
	_, ok := agentForCommand("some-other-agent")
	if ok {
		t.Errorf("agentForCommand(unknown) ok = true, want false")
	}
}

// ---- reassertAgentHook --------------------------------------------------------

// TestReassertAgentHook_RestoresRemovedClaudeHook drives the full shield-side
// path: a tampered ~/.claude/settings.json (hook removed, other keys
// present) gets restored, and a HookReinjected audit event is emitted.
func TestReassertAgentHook_RestoresRemovedClaudeHook(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"keepMe": "yes", "hooks": {"PreToolUse": []}}`), 0o600); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	rec := &recordingEmitter{}
	reassertAgentHook(context.Background(), "claude", rec)

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json after reassert: %v", err)
	}

	hookBin := filepath.Join(tmpHome, ".agentjail", "bin", "agentjail-hook")
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal restored settings: %v", err)
	}
	if root["keepMe"] != "yes" {
		t.Errorf("keepMe = %v, want %q (unrelated keys must be preserved)", root["keepMe"], "yes")
	}
	if !containsHookCmd(t, data, hookBin) {
		t.Errorf("restored settings.json does not contain hook bin %q:\n%s", hookBin, data)
	}

	if len(rec.events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(rec.events))
	}
	if rec.events[0].EventType != audit.HookReinjected {
		t.Errorf("event type = %q, want %q", rec.events[0].EventType, audit.HookReinjected)
	}
}

// TestReassertAgentHook_NoopWhenAlreadyCorrect verifies that a correctly
// registered hook produces no file mutation and no audit event.
func TestReassertAgentHook_NoopWhenAlreadyCorrect(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	rec := &recordingEmitter{}
	// First call installs the hook.
	reassertAgentHook(context.Background(), "claude", rec)

	settingsPath := filepath.Join(tmpHome, ".claude", "settings.json")
	before, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}

	rec.events = nil
	reassertAgentHook(context.Background(), "claude", rec)

	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("settings.json mutated on a no-op reassert:\nbefore: %s\nafter:  %s", before, after)
	}
	if len(rec.events) != 0 {
		t.Errorf("emitted %d events on no-op reassert, want 0", len(rec.events))
	}
}

// TestReassertAgentHook_SkipsUnknownAgent verifies that an agent with no
// known hook-registration mechanism is skipped without touching the
// filesystem or emitting audit events.
func TestReassertAgentHook_SkipsUnknownAgent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	rec := &recordingEmitter{}
	reassertAgentHook(context.Background(), "some-other-agent", rec)

	if len(rec.events) != 0 {
		t.Errorf("emitted %d events for unknown agent, want 0", len(rec.events))
	}
	if _, err := os.Stat(filepath.Join(tmpHome, ".claude")); !os.IsNotExist(err) {
		t.Errorf(".claude directory was created for an unrelated agent command")
	}
}

// containsHookCmd is a light substring check on raw settings JSON, avoiding a
// dependency on internal/agents' unexported helpers.
func containsHookCmd(t *testing.T, data []byte, hookBin string) bool {
	t.Helper()
	return strings.Contains(string(data), hookBin)
}
