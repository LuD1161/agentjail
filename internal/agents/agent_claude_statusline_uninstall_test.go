package agents

import (
	"encoding/json"
	"strings"
	"testing"
)

func statusLineCommand(t *testing.T, raw []byte) (string, bool) {
	t.Helper()
	var root map[string]interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	sl, ok := root["statusLine"].(map[string]interface{})
	if !ok {
		return "", false
	}
	cmd, _ := sl["command"].(string)
	return cmd, true
}

// TestClaudeRemoveStatusLineEntry_RestoresChained is the round-trip that
// matters: a user with their own statusline gets it chained on install and must
// get it back verbatim on uninstall (ADR 0063).
func TestClaudeRemoveStatusLineEntry_RestoresChained(t *testing.T) {
	const userCmd = "cship --fancy"

	settings := []byte(`{"statusLine":{"type":"command","command":"` + userCmd + `"}}`)

	merged, changed := claudeMergeStatusLineEntry(settings, "/home/u/.agentjail/bin/agentjail")
	if !changed {
		t.Fatal("expected merge to chain the foreign statusline")
	}
	if cmd, _ := statusLineCommand(t, merged); !strings.Contains(cmd, "--chain "+userCmd) {
		t.Fatalf("merge did not chain the user command, got %q", cmd)
	}

	removed, changed := claudeRemoveStatusLineEntry(merged)
	if !changed {
		t.Fatal("expected uninstall to rewrite the statusLine")
	}
	cmd, present := statusLineCommand(t, removed)
	if !present {
		t.Fatal("uninstall dropped the user's statusline instead of restoring it")
	}
	if cmd != userCmd {
		t.Errorf("statusline not restored verbatim: got %q, want %q", cmd, userCmd)
	}
}

// TestClaudeRemoveStatusLineEntry_UnchainedIsDeleted: an agentjail statusLine
// with nothing chained had no predecessor, so uninstall removes the key.
func TestClaudeRemoveStatusLineEntry_UnchainedIsDeleted(t *testing.T) {
	settings := []byte(`{"statusLine":{"type":"command","command":"/home/u/.agentjail/bin/agentjail statusline"}}`)

	removed, changed := claudeRemoveStatusLineEntry(settings)
	if !changed {
		t.Fatal("expected our own statusLine to be removed")
	}
	if _, present := statusLineCommand(t, removed); present {
		t.Errorf("statusLine key should be gone:\n%s", removed)
	}
}

// TestClaudeRemoveStatusLineEntry_ForeignUntouched: a statusline agentjail
// never owned must survive uninstall untouched.
func TestClaudeRemoveStatusLineEntry_ForeignUntouched(t *testing.T) {
	settings := []byte(`{"statusLine":{"type":"command","command":"starship prompt"}}`)

	removed, changed := claudeRemoveStatusLineEntry(settings)
	if changed {
		t.Errorf("foreign statusLine must not be touched, got:\n%s", removed)
	}
}

// TestClaudeUninstall_RemovesBothEntries verifies Uninstall clears the hook AND
// the statusLine, so no setting is left invoking the deleted binary.
func TestClaudeUninstall_RemovesBothEntries(t *testing.T) {
	home := t.TempDir()
	env := Env{
		Home:    home,
		BinDir:  home + "/.agentjail/bin",
		HookBin: home + "/.agentjail/bin/agentjail-hook",
		CLIBin:  home + "/.agentjail/bin/agentjail",
	}

	if err := (ClaudeCode{}).Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := (ClaudeCode{}).Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	raw := readSettings(t, env)
	if strings.Contains(string(raw), ".agentjail") {
		t.Errorf("settings.json still references agentjail after uninstall:\n%s", raw)
	}
}
