package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// The fail-open notice must reach the user via systemMessage: Claude Code
// sends hook stderr to the debug log only on an exit-0 allow, so the stderr
// banner alone left daemon-down windows silent for days (ADR 0073).
func TestFailOpenAllowCarriesSystemMessage(t *testing.T) {
	for _, level := range []string{levelAllow, levelDegraded} {
		t.Run(level, func(t *testing.T) {
			msg := failOpenSystemMessage(level)
			if msg == "" {
				t.Fatal("no systemMessage for a fail-open allow — the user sees nothing")
			}
			if !strings.Contains(msg, "agentjail") {
				t.Errorf("systemMessage does not name the tool: %q", msg)
			}
			if !strings.Contains(msg, restartInstructions) {
				t.Errorf("systemMessage omits the recovery command: %q", msg)
			}
		})
	}
}

// A healthy, daemon-answered allow must stay silent — the notice is for
// fail-open only, and systemMessage is omitempty.
func TestNormalAllowHasNoSystemMessage(t *testing.T) {
	out := claudeHookOutput{
		HookSpecificOutput: claudePermissionOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
		},
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "systemMessage") {
		t.Errorf("normal allow leaked a systemMessage: %s", b)
	}
}

// The fail-open allow response must serialize the notice into the JSON that
// Claude Code actually reads.
func TestFailOpenAllowJSONShape(t *testing.T) {
	out := claudeHookOutput{
		HookSpecificOutput: claudePermissionOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
		},
		SystemMessage: failOpenSystemMessage(levelAllow),
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	sm, ok := got["systemMessage"].(string)
	if !ok || sm == "" {
		t.Fatalf("systemMessage missing from fail-open allow response: %s", b)
	}
}

// Codex documents systemMessage as supported for PreToolUse, so its fail-open
// path gets the notice too — but its allow convention is an empty stdout, so
// the response must carry ONLY systemMessage: no permissionDecision (which
// would override default-allow) and none of Claude's hookSpecificOutput
// (which Codex does not read).
func TestCodexFailOpenCarriesOnlySystemMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(codexSystemMessageOutput{
		SystemMessage: failOpenSystemMessage(levelAllow),
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("codex response must carry exactly one field, got %v", got)
	}
	if _, ok := got["systemMessage"]; !ok {
		t.Errorf("codex response missing systemMessage: %v", got)
	}
	for _, forbidden := range []string{"hookSpecificOutput", "permissionDecision", "permissionDecisionReason"} {
		if _, ok := got[forbidden]; ok {
			t.Errorf("codex response leaked %q — Codex does not read it", forbidden)
		}
	}
}

// A healthy Codex allow writes nothing at all; only fail-open speaks up.
func TestWriteCodexSystemMessageEmptyIsSilent(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	writeCodexSystemMessage("")
	w.Close()
	os.Stdout = orig

	out, _ := io.ReadAll(r)
	if len(out) != 0 {
		t.Errorf("empty systemMessage must write nothing, got %q", out)
	}
}
