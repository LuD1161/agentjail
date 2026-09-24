package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUninstallWrapperReportsReadAndParseFailures(t *testing.T) {
	for name, raw := range map[string]string{
		"invalid": `{broken`, "null": `null`, "array": `[]`, "empty": ``,
		"unterminated comment": `{} /*`, "unfinished comment": `/*`,
		"invalid wrapper": `{"claudeCode.claudeProcessWrapper":42}`,
	} {
		t.Run(name, func(t *testing.T) {
			home, path := wrapperCleanupFixture(t, "Code")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := uninstallVSCodeWrapper(home, "Code"); err == nil {
				t.Fatal("malformed settings accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != raw {
				t.Fatalf("settings changed: %q %v", got, err)
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		home, path := wrapperCleanupFixture(t, "Code")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := uninstallVSCodeWrapper(home, "Code"); err == nil {
			t.Fatal("read failure ignored")
		}
	})
}

func TestUninstallWrapperAcceptsJSONCAndPreservesForeignSettings(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprint(owned), func(t *testing.T) {
			home, path := wrapperCleanupFixture(t, "Cursor")
			wrapper := filepath.Join(home, ".agentjail-other", "custom-wrapper")
			if owned {
				wrapper = filepath.Join(home, ".agentjail", "bin", wrapperBinaryName)
			}
			encoded, err := json.Marshal(wrapper)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(fmt.Sprintf(`{
  /* extension configuration */
  "claudeCode.claudeProcessWrapper": %s, // owned or foreign
  "nested": {"list": [1, 2, /* trailing */ ], "text": "https://example.test/a//b,}",},
  "literal": "/* not a comment */",
  "escaped": "quote\" // still inside the string",
  "precise": 9007199254740993,
}`, encoded))
			if err := os.WriteFile(path, raw, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := uninstallVSCodeWrapper(home, "Cursor"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !owned {
				if string(got) != string(raw) {
					t.Fatal("foreign JSONC settings changed")
				}
				return
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(got, &document); err != nil {
				t.Fatal(err)
			}
			if _, present := document[wrapperSettingsKey]; present {
				t.Fatal("owned wrapper survived")
			}
			if string(document["precise"]) != "9007199254740993" {
				t.Fatal("foreign number changed")
			}
			for key, want := range map[string]string{"literal": "/* not a comment */", "escaped": "quote\" // still inside the string"} {
				var value string
				if err := json.Unmarshal(document[key], &value); err != nil || value != want {
					t.Fatalf("%s changed: %q %v", key, value, err)
				}
			}
			if !strings.Contains(string(document["nested"]), "https://example.test/a//b,}") {
				t.Fatal("nested URL changed")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o640 {
				t.Fatalf("settings permissions changed: %v", err)
			}
		})
	}
}

func TestUninstallWrapperPreservesTargetsUntilSettingsCommit(t *testing.T) {
	home, path := wrapperCleanupFixture(t, "Code")
	previous := "/tools/previous-wrapper"
	raw, err := json.Marshal(map[string]string{wrapperSettingsKey: filepath.Join(home, ".agentjail", "bin", wrapperBinaryName), "_agentjail_previous_wrapper": previous})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(home, ".agentjail", "wrapper-chain.conf")
	if err := os.MkdirAll(filepath.Dir(chain), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chain, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	writes := 0
	err = uninstallVSCodeWrapperWithWriter(home, "Code", func(string, []byte, os.FileMode) error {
		writes++
		return errors.New("injected settings commit failure")
	})
	if err == nil || writes != 1 {
		t.Fatalf("write failure ignored: %v writes=%d", err, writes)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(raw) {
		t.Fatal("failed commit changed settings")
	}
	if got, err := os.ReadFile(chain); err != nil || string(got) != previous {
		t.Fatal("failed commit removed live chain")
	}
	if err := uninstallVSCodeWrapper(home, "Code"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]string
	if err := json.Unmarshal(got, &document); err != nil {
		t.Fatal(err)
	}
	if document[wrapperSettingsKey] != previous {
		t.Fatal("previous wrapper not restored")
	}
	if _, present := document["_agentjail_previous_wrapper"]; present {
		t.Fatal("backup entry not removed")
	}
	if _, err := os.Stat(chain); !os.IsNotExist(err) {
		t.Fatalf("chain survived committed settings: %v", err)
	}
}

func TestUninstallWrapperPreservesChainNeededByOtherIDE(t *testing.T) {
	for _, otherState := range []string{"owned", "malformed", "unreadable"} {
		t.Run(otherState, func(t *testing.T) {
			home, codePath := wrapperCleanupFixture(t, "Code")
			cursorPath := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(codePath))), "Cursor", "User", "settings.json")
			if err := os.MkdirAll(filepath.Dir(cursorPath), 0o700); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(map[string]string{wrapperSettingsKey: filepath.Join(home, ".agentjail", "bin", wrapperBinaryName)})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(codePath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			switch otherState {
			case "owned":
				if err := os.WriteFile(cursorPath, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(cursorPath, []byte(`{broken`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Mkdir(cursorPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			chain := filepath.Join(home, ".agentjail", "wrapper-chain.conf")
			if err := os.MkdirAll(filepath.Dir(chain), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(chain, []byte("/tools/previous-wrapper"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := uninstallVSCodeWrapper(home, "Code"); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(chain); err != nil || string(got) != "/tools/previous-wrapper" {
				t.Fatal("other IDE lost the shared wrapper chain")
			}
		})
	}
}

func wrapperCleanupFixture(t *testing.T, app string) (string, string) {
	t.Helper()
	home := t.TempDir()
	var directory string
	switch runtime.GOOS {
	case "darwin":
		directory = filepath.Join(home, "Library", "Application Support", app, "User")
	case "linux":
		directory = filepath.Join(home, ".config", app, "User")
	default:
		t.Skip("IDE wrappers are supported on macOS and Linux")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return home, filepath.Join(directory, "settings.json")
}
