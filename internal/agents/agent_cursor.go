package agents

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Cursor is the agent implementation for the Cursor editor.
// It wires/unwires the agentjail hook in ~/.cursor/hooks.json for the
// enforced blocking events confirmed by T0:
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
	Version int                          `json:"version"`
	Hooks   map[string][]cursorHookEntry `json:"hooks"`
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

	var statusLineData []byte
	var statusLineChanged bool
	if env.CLIBin != "" {
		configPath := cursorCLIConfigPath(env)
		existing, err := os.ReadFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("install cursor: read cli-config.json: %w", err)
		}
		statusLineData, statusLineChanged, err = cursorMergeStatusLineEntry(existing, env.CLIBin)
		if err != nil {
			return fmt.Errorf("install cursor: cli-config.json: %w", err)
		}
	}

	root, err := parseCursorHooks(hooksPath)
	if err != nil {
		return fmt.Errorf("install cursor: %w", err)
	}

	changed := false
	// Older installs registered the Claude/Codex-shaped command without the
	// Cursor adapter flag. Remove only that exact AgentJail command, including
	// its obsolete PreToolUse event, before ensuring the current entries.
	if cursorRemoveLegacyEntries(&root, env.HookBin) {
		changed = true
	}
	for _, event := range cursorHookEvents {
		if !cursorEntryExists(root.Hooks[event], hookCmd) {
			root.Hooks[event] = append(root.Hooks[event], cursorHookEntry{Command: hookCmd})
			changed = true
		}
	}

	if !changed && !statusLineChanged {
		// Already fully installed — nothing to write.
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		return fmt.Errorf("install cursor: mkdir %s: %w", filepath.Dir(hooksPath), err)
	}

	if changed {
		out, err := marshalCursorHooks(root)
		if err != nil {
			return fmt.Errorf("install cursor: marshal hooks.json: %w", err)
		}
		if err := writeFileAtomic(hooksPath, out, 0o600); err != nil {
			return err
		}
	}
	if statusLineChanged {
		if err := writeFileAtomic(cursorCLIConfigPath(env), statusLineData, 0o600); err != nil {
			return fmt.Errorf("install cursor: write cli-config.json: %w", err)
		}
	}
	return nil
}

// Uninstall removes only the agentjail hook entries (those whose command equals
// env.HookBin + " --agent=cursor") from ~/.cursor/hooks.json.
// It is idempotent: if the entries are absent, or the file does not exist,
// Uninstall returns nil. Other hook entries are preserved.
func (Cursor) Uninstall(env Env) error {
	hooksPath := filepath.Join(env.Home, ".cursor", "hooks.json")
	hookCmd := cursorHookCommand(env)

	var statusLineData []byte
	var statusLineChanged bool
	configPath := cursorCLIConfigPath(env)
	if existing, err := os.ReadFile(configPath); err == nil {
		statusLineData, statusLineChanged = cursorRemoveStatusLineEntry(existing)
	}

	hooksExist := true
	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		hooksExist = false
	}

	changed := false
	var root cursorHooksJSON
	var err error
	if hooksExist {
		root, err = parseCursorHooks(hooksPath)
		if err != nil {
			return fmt.Errorf("uninstall cursor: %w", err)
		}
		for _, event := range cursorHookEvents {
			filtered := cursorRemoveEntry(root.Hooks[event], hookCmd)
			if len(filtered) != len(root.Hooks[event]) {
				if len(filtered) == 0 {
					delete(root.Hooks, event)
				} else {
					root.Hooks[event] = filtered
				}
				changed = true
			}
		}
	}

	if !changed && !statusLineChanged {
		return nil
	}

	if changed {
		out, err := marshalCursorHooks(root)
		if err != nil {
			return fmt.Errorf("uninstall cursor: marshal hooks.json: %w", err)
		}
		if err := writeFileAtomic(hooksPath, out, 0o600); err != nil {
			return err
		}
	}
	if statusLineChanged {
		if err := writeFileAtomic(configPath, statusLineData, 0o600); err != nil {
			return fmt.Errorf("uninstall cursor: write cli-config.json: %w", err)
		}
	}
	return nil
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

// cursorRemoveLegacyEntries removes commands written by the pre-Cursor-adapter
// installer. A bare AgentJail hook receives Cursor JSON through the Claude
// adapter and therefore cannot enforce Cursor events correctly.
func cursorRemoveLegacyEntries(root *cursorHooksJSON, legacyCommand string) bool {
	changed := false
	for event, entries := range root.Hooks {
		filtered := cursorRemoveEntry(entries, legacyCommand)
		if len(filtered) == len(entries) {
			continue
		}
		changed = true
		if len(filtered) == 0 {
			delete(root.Hooks, event)
			continue
		}
		root.Hooks[event] = filtered
	}
	return changed
}

func cursorCLIConfigPath(env Env) string {
	return filepath.Join(env.Home, ".cursor", "cli-config.json")
}

const cursorStatuslineFlag = "--chain-base64"
const cursorStatuslineIntegration = "cursor"

func cursorMergeStatusLineEntry(raw []byte, cliBin string) ([]byte, bool, error) {
	root, statusLine, existingCommand, err := parseCursorStatusLine(raw)
	if err != nil {
		return raw, false, err
	}

	command := quotePOSIX(cliBin) + " statusline --integration " + cursorStatuslineIntegration
	if existingCommand != "" {
		if owned, encoded := cursorOwnedStatusLine(existingCommand); owned {
			if encoded != "" {
				command += " " + cursorStatuslineFlag + " " + encoded
			}
		} else {
			encoded := base64.RawStdEncoding.EncodeToString([]byte(existingCommand))
			command += " " + cursorStatuslineFlag + " " + encoded
		}
	}
	if command == existingCommand {
		return raw, false, nil
	}

	statusLine["type"] = json.RawMessage(`"command"`)
	encodedCommand, _ := json.Marshal(command)
	statusLine["command"] = encodedCommand
	encodedStatusLine, err := json.Marshal(statusLine)
	if err != nil {
		return raw, false, fmt.Errorf("marshal statusLine: %w", err)
	}
	root["statusLine"] = encodedStatusLine
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return raw, false, fmt.Errorf("marshal cli-config.json: %w", err)
	}
	return append(out, '\n'), true, nil
}

func cursorRemoveStatusLineEntry(raw []byte) ([]byte, bool) {
	root, statusLine, command, err := parseCursorStatusLine(raw)
	if err != nil {
		return raw, false
	}
	owned, encoded := cursorOwnedStatusLine(command)
	if !owned {
		return raw, false
	}

	if encoded == "" {
		delete(root, "statusLine")
	} else {
		decoded, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return raw, false
		}
		restored, _ := json.Marshal(string(decoded))
		statusLine["command"] = restored
		encodedStatusLine, err := json.Marshal(statusLine)
		if err != nil {
			return raw, false
		}
		root["statusLine"] = encodedStatusLine
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return raw, false
	}
	return append(out, '\n'), true
}

func parseCursorStatusLine(raw []byte) (map[string]json.RawMessage, map[string]json.RawMessage, string, error) {
	root := make(map[string]json.RawMessage)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return nil, nil, "", fmt.Errorf("malformed JSON: %w", err)
		}
	}

	statusLine := make(map[string]json.RawMessage)
	if encoded, ok := root["statusLine"]; ok {
		if err := json.Unmarshal(encoded, &statusLine); err != nil {
			return nil, nil, "", fmt.Errorf("statusLine is not an object: %w", err)
		}
	}
	var command string
	if encoded, ok := statusLine["command"]; ok {
		if err := json.Unmarshal(encoded, &command); err != nil {
			return nil, nil, "", fmt.Errorf("statusLine.command is not a string: %w", err)
		}
	}
	return root, statusLine, command, nil
}

func cursorOwnedStatusLine(command string) (bool, string) {
	fields := strings.Fields(command)
	owned := false
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--integration" && fields[i+1] == cursorStatuslineIntegration {
			owned = true
			break
		}
	}
	if !owned {
		return false, ""
	}
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == cursorStatuslineFlag {
			return true, fields[i+1]
		}
	}
	return true, ""
}

func quotePOSIX(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
