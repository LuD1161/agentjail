package agents

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/internal/agentguidance"
)

// ClaudeCode is the agent implementation for Anthropic's Claude Code.
// It wires/unwires AgentJail's policy and outcome hooks in settings.json.
type ClaudeCode struct{}

// ID returns "claude-code".
func (ClaudeCode) ID() string { return "claude-code" }

// DisplayName returns "Claude Code".
func (ClaudeCode) DisplayName() string { return "Claude Code" }

// Detect reports whether ~/.claude/ exists under env.Home.
func (ClaudeCode) Detect(env Env) Detection {
	dir := filepath.Join(env.Home, ".claude")
	if _, err := os.Stat(dir); err == nil {
		return Detection{Present: true, Evidence: "~/.claude exists"}
	}
	return Detection{Present: false}
}

// Install merges a PreToolUse hook entry for env.HookBin into
// ~/.claude/settings.json. The operation is idempotent: if the entry is
// already present the file is not rewritten.
//
// Defensive rules:
//   - If settings.json exists but contains malformed JSON, Install returns an
//     error and leaves the file byte-for-byte unchanged.
//   - Unknown top-level keys are preserved.
//   - The file is written via writeFileAtomic (0600 mode).
func (ClaudeCode) Install(env Env) error {
	settingsPath := filepath.Join(env.Home, ".claude", "settings.json")

	var existing []byte
	if b, err := os.ReadFile(settingsPath); err == nil {
		existing = b
		// Validate JSON before attempting any merge; do NOT treat malformed
		// JSON as empty — leave the file untouched and return an error.
		var probe interface{}
		if jsonErr := json.Unmarshal(existing, &probe); jsonErr != nil {
			return fmt.Errorf("install claude-code: settings.json is malformed JSON: %w", jsonErr)
		}
	}

	updated, hookChanged := claudeMergeHookEntry(existing, env.HookBin)

	statusLineChanged := false
	if env.CLIBin != "" {
		updated, statusLineChanged = claudeMergeStatusLineEntry(updated, env.CLIBin)
	}

	if hookChanged || statusLineChanged {
		if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
			return fmt.Errorf("install claude-code: mkdir %s: %w", filepath.Dir(settingsPath), err)
		}
		if err := writeFileAtomic(settingsPath, updated, 0o600); err != nil {
			return err
		}
	}
	if err := (ClaudeCode{}).ReconcileGuidance(env); err != nil {
		return fmt.Errorf("install claude-code: CLAUDE.md: %w", err)
	}
	return nil
}

// Uninstall removes the agentjail hook entry for env.HookBin and the agentjail
// statusLine entry from ~/.claude/settings.json, restoring any statusline that
// was preserved by chaining. It is idempotent: if neither is present, or the
// file does not exist, Uninstall returns nil.
//
// Both must be removed: Install writes both, so removing only the hook leaves a
// statusLine invoking a binary uninstall just deleted (ADR 0063).
func (ClaudeCode) Uninstall(env Env) error {
	settingsPath := filepath.Join(env.Home, ".claude", "settings.json")
	guidanceErr := removeClaudeGuidance(env)

	existing, err := os.ReadFile(settingsPath)
	if os.IsNotExist(err) {
		return guidanceErr
	}
	if err != nil {
		return errors.Join(fmt.Errorf("uninstall claude-code: read settings.json: %w", err), guidanceErr)
	}

	updated := claudeRemoveHookEntry(existing, env.HookBin)
	updated, _ = claudeRemoveStatusLineEntry(updated)
	if string(updated) == string(existing) {
		return guidanceErr
	}

	return errors.Join(writeFileAtomic(settingsPath, updated, 0o600), guidanceErr)
}

// ReconcileGuidance refreshes AgentJail's owned block in Claude Code's global
// instruction file.
func (ClaudeCode) ReconcileGuidance(env Env) error {
	_, err := agentguidance.Reconcile(filepath.Join(env.Home, ".claude", "CLAUDE.md"))
	return err
}

func removeClaudeGuidance(env Env) error {
	path := filepath.Join(env.Home, ".claude", "CLAUDE.md")
	_, err := agentguidance.Remove(path)
	if err != nil {
		return fmt.Errorf("remove AgentJail guidance from %s: %w", path, err)
	}
	return nil
}

// Status reports whether the agentjail hook entry for env.HookBin is present
// in ~/.claude/settings.json.
func (ClaudeCode) Status(env Env) Status {
	settingsPath := filepath.Join(env.Home, ".claude", "settings.json")
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		return Status{Installed: false}
	}
	_, changed := claudeMergeHookEntry(b, env.HookBin)
	// If no change is needed, the hook is already present.
	return Status{Installed: !changed}
}

// ---- pure JSON helpers (ported from cmd/agentjail/install.go) ----------------
//
// These are intentionally unexported copies rather than a shared import so
// that the agents package remains self-contained and install.go continues to
// own its own copy for the existing orchestration path (T6 will unify them).

// claudeMergeHookEntry merges a PreToolUse hook entry for hookCmd into raw
// settings JSON. It returns the updated JSON and whether a change was made.
//
// Unlike the cmd/agentjail version, this function does NOT treat malformed
// JSON as empty — the caller (Install) must validate before calling this.
// If settings is nil or empty, a fresh object is created.
func claudeMergeHookEntry(settings []byte, hookCmd string) ([]byte, bool) {
	var root map[string]interface{}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &root); err != nil {
			// Caller should have validated; be safe and create fresh.
			root = nil
		}
	}
	if root == nil {
		root = make(map[string]interface{})
	}

	hooks, _ := root["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
	}

	// The same hook binary is wired for the policy decision and both outcome
	// events. Claude Code 2.1.216 separates successful and failed tool calls.
	// See ADR 0112-final-action-outcome.
	changed := false
	for _, event := range claudeHookEvents {
		list, _ := hooks[event].([]interface{})
		if claudeHookEntryExists(list, hookCmd) {
			continue
		}
		list = append(list, map[string]interface{}{
			"matcher": "*",
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": hookCmd,
				},
			},
		})
		hooks[event] = list
		changed = true
	}
	if !changed {
		return settings, false
	}
	root["hooks"] = hooks

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return settings, false
	}
	out = append(out, '\n')
	return out, true
}

// claudeHookEvents are the lifecycle seams AgentJail owns. PostToolUse cannot
// prove failure; PostToolUseFailure carries the typed failure evidence.
var claudeHookEvents = []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"}

// claudeStatuslineSuffix is appended to the agentjail CLI binary path to form
// the command agentjail owns in Claude Code's statusLine setting.
const claudeStatuslineSuffix = " statusline"

// claudeMergeStatusLineEntry merges an agentjail statusLine entry into raw
// settings JSON. It returns the updated JSON and whether a change was made.
//
// Behavior:
//   - No existing statusLine: set ours (`<cliBin> statusline`).
//   - Existing statusLine is structurally ours (its second field is
//     literally "statusline", i.e. it was produced by a previous run of this
//     function): refresh the binary path in place, preserving any trailing
//     `--chain ...` it carries. This covers cliBin changing across installs
//     (e.g. reinstalled to a new BinDir) without accumulating a chain and
//     without losing a previously-preserved foreign command.
//   - Existing statusLine belongs to something else entirely: preserve it by
//     chaining via the `--chain` flag (`<cliBin> statusline --chain
//     <existing cmd>`), so the user's own statusline output is never lost.
//
// If settings is nil or empty, a fresh object is created.
func claudeMergeStatusLineEntry(settings []byte, cliBin string) ([]byte, bool) {
	var root map[string]interface{}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &root); err != nil {
			// Caller should have validated; be safe and create fresh.
			root = nil
		}
	}
	if root == nil {
		root = make(map[string]interface{})
	}

	ourCommand := cliBin + claudeStatuslineSuffix

	existing, _ := root["statusLine"].(map[string]interface{})
	newCommand := ourCommand
	if existing != nil {
		existingCmd, _ := existing["command"].(string)
		if existingCmd != "" {
			fields := strings.Fields(existingCmd)
			if len(fields) >= 2 && fields[1] == "statusline" {
				// Structurally ours: refresh the binary path but keep
				// whatever trails "<bin> statusline" (e.g. "--chain foo").
				remainder := strings.TrimPrefix(existingCmd, fields[0]+claudeStatuslineSuffix)
				newCommand = ourCommand + remainder
			} else {
				// Foreign statusLine — preserve it by chaining.
				newCommand = ourCommand + " --chain " + existingCmd
			}
			if newCommand == existingCmd {
				// Already converged — nothing to do.
				return settings, false
			}
		}
	}

	root["statusLine"] = map[string]interface{}{
		"type":    "command",
		"command": newCommand,
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return settings, false
	}
	return append(out, '\n'), true
}

// claudeRemoveStatusLineEntry inverts claudeMergeStatusLineEntry. It returns
// the updated JSON and whether a change was made.
//
// Behavior:
//   - statusLine is not structurally ours (or absent): left untouched. A user
//     who set their own statusline after installing keeps it.
//   - Ours, carrying `--chain <cmd>`: restore <cmd> as the statusLine. The
//     merge preserved a foreign statusline by chaining it; uninstall must hand
//     it back, or the user silently loses a statusline agentjail never owned.
//   - Ours, with no chain: remove the statusLine key entirely.
//
// Without this, uninstall leaves a statusLine pointing at the deleted agentjail
// binary. See ADR 0063.
func claudeRemoveStatusLineEntry(settings []byte) ([]byte, bool) {
	if len(settings) == 0 {
		return settings, false
	}
	var root map[string]interface{}
	if err := json.Unmarshal(settings, &root); err != nil {
		return settings, false
	}

	existing, _ := root["statusLine"].(map[string]interface{})
	if existing == nil {
		return settings, false
	}
	existingCmd, _ := existing["command"].(string)
	fields := strings.Fields(existingCmd)
	if len(fields) < 2 || fields[1] != "statusline" {
		return settings, false // not ours
	}

	remainder := strings.TrimSpace(strings.TrimPrefix(existingCmd, fields[0]+claudeStatuslineSuffix))
	if chained := strings.TrimSpace(strings.TrimPrefix(remainder, "--chain")); remainder != "" && chained != remainder {
		// We wrapped someone else's statusline — give it back verbatim.
		root["statusLine"] = map[string]interface{}{
			"type":    "command",
			"command": chained,
		}
	} else {
		delete(root, "statusLine")
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return settings, false
	}
	return append(out, '\n'), true
}

// claudeRemoveHookEntry removes any PreToolUse entry whose command matches
// hookCmd from raw settings JSON. Returns the updated JSON (unchanged if
// hookCmd was not present).
func claudeRemoveHookEntry(settings []byte, hookCmd string) []byte {
	if len(settings) == 0 {
		return settings
	}
	var root map[string]interface{}
	if err := json.Unmarshal(settings, &root); err != nil {
		return settings
	}

	hooks, _ := root["hooks"].(map[string]interface{})
	if hooks == nil {
		return settings
	}

	// Remove the hook from every event it was wired into.
	changed := false
	for _, event := range claudeHookEvents {
		list, _ := hooks[event].([]interface{})
		if list == nil {
			continue
		}
		filtered := list[:0]
		for _, entry := range list {
			em, _ := entry.(map[string]interface{})
			if em != nil && claudeEntryHasCommand(em, hookCmd) {
				continue // drop this entry
			}
			filtered = append(filtered, entry)
		}
		if len(filtered) != len(list) {
			hooks[event] = filtered
			changed = true
		}
	}
	if !changed {
		return settings
	}
	root["hooks"] = hooks

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return settings
	}
	return append(out, '\n')
}

// claudeHookEntryExists reports whether hookCmd appears in any entry in
// preToolUse.
func claudeHookEntryExists(preToolUse []interface{}, hookCmd string) bool {
	for _, entry := range preToolUse {
		em, _ := entry.(map[string]interface{})
		if em == nil {
			continue
		}
		if claudeEntryHasCommand(em, hookCmd) {
			return true
		}
	}
	return false
}

// claudeEntryHasCommand reports whether the PreToolUse entry map contains
// hookCmd as a command in its hooks list.
func claudeEntryHasCommand(entry map[string]interface{}, hookCmd string) bool {
	inner, _ := entry["hooks"].([]interface{})
	for _, h := range inner {
		hm, _ := h.(map[string]interface{})
		if hm == nil {
			continue
		}
		if hm["command"] == hookCmd {
			return true
		}
	}
	return false
}
