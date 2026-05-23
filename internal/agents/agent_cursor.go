package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Cursor is the agent implementation for the Cursor editor.
// It wires/unwires the agentjail hook in ~/.cursor/hooks.json for the
// three enforced blocking events confirmed by T0:
// beforeShellExecution, beforeMCPExecution, beforeReadFile.
type Cursor struct{}

// ID returns "cursor".
func (Cursor) ID() string { return "cursor" }

// DisplayName returns "Cursor".
func (Cursor) DisplayName() string { return "Cursor" }

// Detect reports whether ~/.cursor/ exists under env.Home.
func (Cursor) Detect(env Env) Detection {
	dir := filepath.Join(env.Home, ".cursor")
	if _, err := os.Stat(dir); err == nil {
		return Detection{Present: true, Evidence: "~/.cursor exists"}
	}
	return Detection{Present: false}
}

// cursorHookEvents is the T0-confirmed set of enforced blocking events that
// agentjail registers on in Cursor.
var cursorHookEvents = []string{
	"beforeShellExecution",
	"beforeMCPExecution",
	"beforeReadFile",
}

// cursorHookEntry is a single hook command entry for a Cursor event.
// Cursor's hooks.json schema (T0 confirmed): {"command": "<cmd>"}
type cursorHookEntry struct {
	Command string `json:"command"`
}

// cursorHooksJSON is the on-disk shape of ~/.cursor/hooks.json.
// "version":1 is required by Cursor (T0 confirmed).
type cursorHooksJSON struct {
	Version int                              `json:"version"`
	Hooks   map[string][]cursorHookEntry     `json:"hooks"`
}

// cursorHookCommand returns the command string agentjail registers in Cursor.
func cursorHookCommand(env Env) string {
	return env.HookBin + " --agent=cursor"
}

// Install writes/merges ~/.cursor/hooks.json with our hook entries on the
// three T0-confirmed events. It is idempotent: if all entries are already
// present the file is not rewritten.
//
// Defensive rules:
//   - If hooks.json exists but contains malformed JSON, Install returns an
//     error and leaves the file byte-for-byte unchanged.
//   - User-defined hooks for any event are preserved.
//   - Duplicate agentjail entries are not added.
//   - Written via writeFileAtomic (0600 mode); .bak on first mutation.
func (Cursor) Install(env Env) error {
	hooksPath := filepath.Join(env.Home, ".cursor", "hooks.json")
	hookCmd := cursorHookCommand(env)

	root, err := parseCursorHooks(hooksPath)
	if err != nil {
		return fmt.Errorf("install cursor: %w", err)
	}

	changed := false
	for _, event := range cursorHookEvents {
		if !cursorEntryExists(root.Hooks[event], hookCmd) {
			root.Hooks[event] = append(root.Hooks[event], cursorHookEntry{Command: hookCmd})
			changed = true
		}
	}

	if !changed {
		// Already fully installed — nothing to write.
		return nil
	}

	out, err := marshalCursorHooks(root)
	if err != nil {
		return fmt.Errorf("install cursor: marshal hooks.json: %w", err)
	}

	// Preserve file mode; default 0600 for new files.
	mode := os.FileMode(0o600)
	if fi, statErr := os.Stat(hooksPath); statErr == nil {
		mode = fi.Mode().Perm()
	}

	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		return fmt.Errorf("install cursor: mkdir %s: %w", filepath.Dir(hooksPath), err)
	}

	return writeFileAtomic(hooksPath, out, mode)
}

// Uninstall removes only the agentjail hook entries (those whose command equals
// env.HookBin + " --agent=cursor") from ~/.cursor/hooks.json.
// It is idempotent: if the entries are absent, or the file does not exist,
// Uninstall returns nil. Other hook entries are preserved.
func (Cursor) Uninstall(env Env) error {
	hooksPath := filepath.Join(env.Home, ".cursor", "hooks.json")
	hookCmd := cursorHookCommand(env)

	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		return nil
	}

	root, err := parseCursorHooks(hooksPath)
	if err != nil {
		return fmt.Errorf("uninstall cursor: %w", err)
	}

	changed := false
	for _, event := range cursorHookEvents {
		filtered := cursorRemoveEntry(root.Hooks[event], hookCmd)
		if len(filtered) != len(root.Hooks[event]) {
			root.Hooks[event] = filtered
			changed = true
		}
	}

	if !changed {
		return nil
	}

	out, err := marshalCursorHooks(root)
	if err != nil {
		return fmt.Errorf("uninstall cursor: marshal hooks.json: %w", err)
	}

	mode := os.FileMode(0o600)
	if fi, statErr := os.Stat(hooksPath); statErr == nil {
		mode = fi.Mode().Perm()
	}

	return writeFileAtomic(hooksPath, out, mode)
}

// Status reports whether our hook entries are present in ~/.cursor/hooks.json
// for all three T0-confirmed events.
func (Cursor) Status(env Env) Status {
	hooksPath := filepath.Join(env.Home, ".cursor", "hooks.json")
	hookCmd := cursorHookCommand(env)

	root, err := parseCursorHooks(hooksPath)
	if err != nil {
		return Status{Installed: false}
	}

	for _, event := range cursorHookEvents {
		if !cursorEntryExists(root.Hooks[event], hookCmd) {
			return Status{Installed: false}
		}
	}
	return Status{Installed: true}
}

// ---- pure JSON helpers -------------------------------------------------------

// parseCursorHooks reads and parses ~/.cursor/hooks.json. Returns a fresh
// empty structure (version=1) when the file does not exist. Returns an error
// (file untouched guarantee rests with caller) when the file is malformed.
func parseCursorHooks(path string) (cursorHooksJSON, error) {
	root := cursorHooksJSON{
		Version: 1,
		Hooks:   make(map[string][]cursorHookEntry),
	}

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return root, nil
	}
	if err != nil {
		return root, fmt.Errorf("read cursor hooks.json: %w", err)
	}

	if jsonErr := json.Unmarshal(b, &root); jsonErr != nil {
		return root, fmt.Errorf("hooks.json is malformed JSON: %w", jsonErr)
	}

	// Ensure version and hooks map are sane.
	if root.Version == 0 {
		root.Version = 1
	}
	if root.Hooks == nil {
		root.Hooks = make(map[string][]cursorHookEntry)
	}

	return root, nil
}

// marshalCursorHooks serialises root to indented JSON with a trailing newline.
func marshalCursorHooks(root cursorHooksJSON) ([]byte, error) {
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// cursorEntryExists reports whether hookCmd already appears in entries.
func cursorEntryExists(entries []cursorHookEntry, hookCmd string) bool {
	for _, e := range entries {
		if strings.TrimSpace(e.Command) == strings.TrimSpace(hookCmd) {
			return true
		}
	}
	return false
}

// cursorRemoveEntry returns a new slice with all entries matching hookCmd
// removed. Does not modify the original slice.
func cursorRemoveEntry(entries []cursorHookEntry, hookCmd string) []cursorHookEntry {
	var out []cursorHookEntry
	for _, e := range entries {
		if strings.TrimSpace(e.Command) != strings.TrimSpace(hookCmd) {
			out = append(out, e)
		}
	}
	return out
}
