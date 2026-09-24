package agents

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUninstallRejectsMalformedHookSettingsWithoutWriting(t *testing.T) {
	for _, adapter := range []struct {
		name      string
		agent     Agent
		dir, file string
	}{
		{"claude", ClaudeCode{}, ".claude", "settings.json"},
		{"codex", Codex{}, ".codex", "hooks.json"},
	} {
		for name, raw := range map[string]string{
			"invalid JSON":    `{"hooks":`,
			"null root":       `null`,
			"array root":      `[]`,
			"null hooks":      `{"hooks":null}`,
			"array hooks":     `{"hooks":[]}`,
			"object event":    `{"hooks":{"PreToolUse":{}}}`,
			"null event":      `{"hooks":{"PreToolUse":null}}`,
			"null group":      `{"hooks":{"PreToolUse":[null]}}`,
			"numeric matcher": `{"hooks":{"PreToolUse":[{"matcher":42,"hooks":[]}]}}`,
			"object entries":  `{"hooks":{"PreToolUse":[{"hooks":{}}]}}`,
			"null entry":      `{"hooks":{"PreToolUse":[{"hooks":[null]}]}}`,
			"numeric command": `{"hooks":{"PreToolUse":[{"hooks":[{"command":42}]}]}}`,
			"null command":    `{"hooks":{"PreToolUse":[{"hooks":[{"command":null}]}]}}`,
			"numeric type":    `{"hooks":{"PreToolUse":[{"hooks":[{"type":42,"command":"foreign"}]}]}}`,
		} {
			t.Run(adapter.name+"/"+name, func(t *testing.T) {
				env := newClaudeEnvWithCLI(t)
				path := filepath.Join(env.Home, adapter.dir, adapter.file)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := adapter.agent.Uninstall(env); err == nil {
					t.Fatal("malformed settings accepted")
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != raw {
					t.Fatalf("settings changed: %s", got)
				}
			})
		}
	}
}

func TestUninstallPreservesForeignHookSiblingsAndFields(t *testing.T) {
	for _, adapter := range []struct {
		name              string
		agent             Agent
		dir, file, suffix string
	}{
		{"claude", ClaudeCode{}, ".claude", "settings.json", ""},
		{"codex", Codex{}, ".codex", "hooks.json", " --agent=codex"},
	} {
		t.Run(adapter.name, func(t *testing.T) {
			env := newClaudeEnvWithCLI(t)
			foreign := map[string]any{"type": "command", "command": "/tools/other-hook", "extension": map[string]any{"future": true}}
			group := map[string]any{"matcher": "Bash", "groupMetadata": "preserved", "hooks": []any{
				map[string]any{"type": "command", "command": env.HookBin + adapter.suffix}, foreign,
			}}
			root := map[string]any{
				"hooks":         map[string]any{"PreToolUse": []any{group}, "FutureEvent": map[string]any{"unknown": true}},
				"futureSetting": json.RawMessage(`9007199254740993`),
			}
			raw, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(env.Home, adapter.dir, adapter.file)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := adapter.agent.Uninstall(env); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			group["hooks"] = []any{foreign}
			want, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			assertCleanupJSONEqual(t, got, want)
			if err := adapter.agent.Uninstall(env); err != nil {
				t.Fatal(err)
			}
			again, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(got) {
				t.Fatal("second uninstall rewrote foreign settings")
			}
		})
	}
}

func TestClaudeUninstallRejectsMalformedStatuslineWithoutRemovingHook(t *testing.T) {
	for _, statusline := range []string{`null`, `[]`, `{"command":42}`, `{"type":false,"command":"foreign"}`} {
		t.Run(statusline, func(t *testing.T) {
			env := newClaudeEnvWithCLI(t)
			if err := (ClaudeCode{}).Install(env); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(env.Home, ".claude", "settings.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]json.RawMessage
			if err := json.Unmarshal(raw, &root); err != nil {
				t.Fatal(err)
			}
			root["statusLine"] = json.RawMessage(statusline)
			raw, err = json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := (ClaudeCode{}).Uninstall(env); err == nil {
				t.Fatal("malformed statusline accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(raw) {
				t.Fatal("failed cleanup changed settings")
			}
		})
	}
}

func TestClaudeUninstallPreservesUnrelatedStatuslineCommands(t *testing.T) {
	for _, command := range []string{
		"/tools/other statusline", "/tools/other statusline --chain prompt", "/foreign/agentjail statusline",
		"/tools/other statusline --chainable prompt",
	} {
		t.Run(command, func(t *testing.T) {
			env := newClaudeEnvWithCLI(t)
			raw, err := json.Marshal(map[string]any{"statusLine": map[string]any{"type": "command", "command": command}})
			if err != nil {
				t.Fatal(err)
			}
			got, changed, err := claudeRemoveStatusLineEntry(raw, env.CLIBin)
			if err != nil {
				t.Fatal(err)
			}
			if changed || string(got) != string(raw) {
				t.Fatalf("foreign statusline removed: %s", got)
			}
		})
	}
}

func TestCursorUninstallPreservesUnknownHookFields(t *testing.T) {
	env := newCursorEnv(t)
	foreign := map[string]any{"command": "/tools/other-hook", "future": true}
	root := map[string]any{
		"version": 1, "futureSetting": json.RawMessage(`9007199254740993`),
		"hooks": map[string]any{
			"beforeShellExecution": []any{map[string]any{"command": cursorHookCommand(env)}, foreign},
			"FutureEvent":          map[string]any{"unknown": true},
		},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.Home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Cursor{}).Uninstall(env); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root["hooks"].(map[string]any)["beforeShellExecution"] = []any{foreign}
	want, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	assertCleanupJSONEqual(t, got, want)
}

func TestCursorUninstallRejectsMalformedConfigWithoutWriting(t *testing.T) {
	for file, inputs := range map[string][]string{
		"hooks.json":      {`null`, `{"hooks":null}`, `{"hooks":{"beforeShellExecution":{}}}`, `{"hooks":{"beforeShellExecution":[null]}}`, `{"hooks":{"beforeShellExecution":[{"command":false}]}}`},
		"cli-config.json": {``, `null`, `{"statusLine":null}`, `{"statusLine":{"command":42}}`},
	} {
		for _, raw := range inputs {
			t.Run(file+"/"+raw, func(t *testing.T) {
				env := newCursorEnv(t)
				if err := (Cursor{}).Install(env); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(env.Home, ".cursor", file)
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
				hooksPath := filepath.Join(env.Home, ".cursor", "hooks.json")
				before, err := os.ReadFile(hooksPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := (Cursor{}).Uninstall(env); err == nil {
					t.Fatal("malformed config accepted")
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != raw {
					t.Fatal("malformed config changed")
				}
				after, err := os.ReadFile(hooksPath)
				if err != nil {
					t.Fatal(err)
				}
				if string(after) != string(before) {
					t.Fatal("hooks changed after cleanup failure")
				}
			})
		}
	}
}

func TestUninstallReportsUnreadableSettings(t *testing.T) {
	for _, adapter := range []struct {
		name      string
		agent     Agent
		dir, file string
	}{
		{"claude", ClaudeCode{}, ".claude", "settings.json"},
		{"codex", Codex{}, ".codex", "hooks.json"},
		{"cursor", Cursor{}, ".cursor", "hooks.json"},
	} {
		t.Run(adapter.name, func(t *testing.T) {
			env := newClaudeEnv(t)
			path := filepath.Join(env.Home, adapter.dir, adapter.file)
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := adapter.agent.Uninstall(env); err == nil {
				t.Fatal("settings read failure ignored")
			}
			if info, err := os.Stat(path); err != nil || !info.IsDir() {
				t.Fatal("failed cleanup replaced settings directory")
			}
		})
	}
}

func assertCleanupJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue map[string]json.RawMessage
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	// Compact each raw value so formatting changes do not hide numeric loss.
	for key, raw := range gotValue {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		gotValue[key], _ = json.Marshal(value)
	}
	for key, raw := range wantValue {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		wantValue[key], _ = json.Marshal(value)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}
