// install_wrapper.go — VS Code/Cursor process wrapper and PATH shim installation.
//
// The VS Code/Cursor wrappers are installed by --for vscode, --for cursor, or
// --all. The PATH shim is opt-in and installed ONLY by --with-path-shim —
// never by --all, which is what `curl | sh` runs (see install.go). Once opted
// in, reassertPathShim keeps it alive across reinstalls (ADR 0062).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	wrapperBinaryName  = "agentjail-wrapper"
	wrapperSettingsKey = "claudeCode.claudeProcessWrapper"
)

// installVSCodeWrapper configures claudeCode.claudeProcessWrapper in the
// VS Code or Cursor user settings to point to the agentjail wrapper binary.
//
// Handles three cases:
//   - Not set: sets it to our wrapper path.
//   - Already set to our wrapper: skips with a message.
//   - Set to something else: does NOT overwrite. Prints instructions for
//     --chain or --replace.
func installVSCodeWrapper(home string, app string, chain, replace bool) error {
	settingsPath := vscodeSettingsPath(home, app)
	if settingsPath == "" {
		return fmt.Errorf("%s not detected on this machine (no settings directory)", app)
	}

	wrapperBin := filepath.Join(home, ".agentjail", "bin", wrapperBinaryName)

	// Ensure the wrapper binary exists.
	if _, err := os.Stat(wrapperBin); os.IsNotExist(err) {
		return fmt.Errorf("wrapper binary not found at %s — run `agentjail install` first", wrapperBin)
	}

	// Read existing settings (may not exist yet).
	var raw []byte
	if b, err := os.ReadFile(settingsPath); err == nil {
		raw = b
	}

	// Parse as JSON (tolerant of empty/missing file).
	settings := make(map[string]interface{})
	if len(raw) > 0 {
		if err := json.Unmarshal(stripJSONComments(raw), &settings); err != nil {
			return fmt.Errorf("%s settings.json is not valid JSON: %v\n  Path: %s\n  Fix the JSON manually, then re-run this command.", app, err, settingsPath)
		}
	}

	existing, hasExisting := settings[wrapperSettingsKey]
	existingStr, _ := existing.(string)

	// Case 1: already set to our wrapper.
	if hasExisting && isOurWrapper(existingStr, home) {
		fmt.Fprintf(os.Stdout, "  %s: agentjail wrapper already configured — skipping\n", app)
		return nil
	}

	// Case 2: set to someone else's wrapper.
	if hasExisting && existingStr != "" {
		if !chain && !replace {
			fmt.Fprintf(os.Stderr, "  %s: claudeProcessWrapper is already set to: %s\n", app, existingStr)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  agentjail will not overwrite an existing wrapper.")
			fmt.Fprintln(os.Stderr, "  Options:")
			fmt.Fprintf(os.Stderr, "    agentjail install --for %s --chain     Chain: agentjail wraps the existing wrapper\n", strings.ToLower(app))
			fmt.Fprintf(os.Stderr, "    agentjail install --for %s --replace   Replace: overwrite with agentjail wrapper (backs up current value)\n", strings.ToLower(app))
			return fmt.Errorf("existing wrapper detected — choose --chain or --replace")
		}

		if replace {
			// Back up the current value in a comment-like key.
			settings["_agentjail_previous_wrapper"] = existingStr
			fmt.Fprintf(os.Stdout, "  %s: backed up existing wrapper: %s\n", app, existingStr)
		}

		if chain {
			// Write the chain config: our wrapper calls theirs.
			chainPath := filepath.Join(home, ".agentjail", "wrapper-chain.conf")
			if err := os.WriteFile(chainPath, []byte(existingStr+"\n"), 0o600); err != nil {
				return fmt.Errorf("failed to write chain config: %v", err)
			}
			fmt.Fprintf(os.Stdout, "  %s: chaining agentjail wrapper → %s\n", app, existingStr)
		}
	}

	// Case 3: not set, or replace/chain mode. Set it.
	settings[wrapperSettingsKey] = wrapperBin

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %v", err)
	}
	out = append(out, '\n')

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		return fmt.Errorf("failed to create settings directory: %v", err)
	}

	// Write atomically (use a temp file + rename).
	tmpPath := settingsPath + ".agentjail-tmp"
	if err := os.WriteFile(tmpPath, out, 0o600); err != nil {
		return fmt.Errorf("failed to write settings: %v", err)
	}
	if err := os.Rename(tmpPath, settingsPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename settings: %v", err)
	}

	fmt.Fprintf(os.Stdout, "  %s: wrapper configured at %s\n", app, settingsPath)
	fmt.Fprintf(os.Stdout, "  %s: restart %s to activate\n", app, app)
	return nil
}

// uninstallVSCodeWrapper removes the agentjail wrapper from VS Code/Cursor settings.
// If a previous wrapper was backed up, it restores it.
func uninstallVSCodeWrapper(home string, app string) error {
	settingsPath := vscodeSettingsPath(home, app)
	if settingsPath == "" {
		return nil // not installed
	}

	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil // no settings file
	}

	settings := make(map[string]interface{})
	if err := json.Unmarshal(stripJSONComments(raw), &settings); err != nil {
		return nil // can't parse, don't touch
	}

	existing, _ := settings[wrapperSettingsKey].(string)
	if !isOurWrapper(existing, home) {
		return nil // not our wrapper, don't touch
	}

	// Restore previous wrapper if backed up.
	if prev, ok := settings["_agentjail_previous_wrapper"].(string); ok && prev != "" {
		settings[wrapperSettingsKey] = prev
		delete(settings, "_agentjail_previous_wrapper")
		fmt.Fprintf(os.Stdout, "  %s: restored previous wrapper: %s\n", app, prev)
	} else {
		delete(settings, wrapperSettingsKey)
		fmt.Fprintf(os.Stdout, "  %s: wrapper removed\n", app)
	}

	// Also clean up chain config.
	chainPath := filepath.Join(home, ".agentjail", "wrapper-chain.conf")
	os.Remove(chainPath)

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(settingsPath, out, 0o600)
}

// installPathShim creates a claude shim binary at ~/.agentjail/bin/claude
// and adds ~/.agentjail/bin to the shell profile PATH.
func installPathShim(home string) error {
	shimDir := filepath.Join(home, ".agentjail", "bin")
	shimPath := filepath.Join(shimDir, "claude")

	shieldBin, err := findShieldBinary(home)
	if err != nil {
		return fmt.Errorf("cannot install PATH shim: shield binary not found — run `agentjail install` first")
	}

	// Create a shell script shim (not a compiled binary — simpler for now).
	shimContent := fmt.Sprintf(`#!/bin/sh
# agentjail PATH shim — transparently wraps claude with agentjail-shield.
# Installed by: agentjail install --with-path-shim
# Remove with:  agentjail uninstall

set -e

# Find the real claude binary, excluding our own directory.
find_real_claude() {
    # Save and modify PATH to exclude our directory.
    _orig_path="$PATH"
    _shim_dir="%s"
    PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "^${_shim_dir}$" | tr '\n' ':' | sed 's/:$//')
    _real=$(command -v claude 2>/dev/null || true)
    PATH="$_orig_path"
    echo "$_real"
}

REAL_CLAUDE=$(find_real_claude)

if [ -z "$REAL_CLAUDE" ]; then
    echo "ERROR: claude not found in PATH (excluding %s)" >&2
    echo "  Install Claude Code, or remove the shim: rm %s" >&2
    exit 127
fi

# Guard against loop: if real claude IS this script, abort.
if [ "$REAL_CLAUDE" = "%s" ]; then
    echo "ERROR: PATH shim resolved to itself at %s" >&2
    echo "  Check your PATH order." >&2
    exit 1
fi

exec "%s" -- "$REAL_CLAUDE" "$@"
`, shimDir, shimDir, shimPath, shimPath, shimPath, shieldBin)

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("failed to create shim directory: %v", err)
	}

	if err := os.WriteFile(shimPath, []byte(shimContent), 0o755); err != nil {
		return fmt.Errorf("failed to write shim: %v", err)
	}

	fmt.Fprintf(os.Stdout, "  PATH shim installed at %s\n", shimPath)

	// Add to shell profile if not already present.
	if err := addToShellProfile(home, shimDir); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not update shell profile: %v\n", err)
		fmt.Fprintf(os.Stderr, "  Add this to your shell profile manually:\n")
		fmt.Fprintf(os.Stderr, "    export PATH=\"%s:$PATH\"\n", shimDir)
	}

	fmt.Fprintln(os.Stdout, "  Run `hash -r` or open a new shell to activate.")
	return nil
}

// uninstallPathShim removes the shim binary. Shell profile cleanup is
// handled by the existing cleanupShellRCPath in install.go.
func uninstallPathShim(home string) {
	shimPath := filepath.Join(home, ".agentjail", "bin", "claude")
	os.Remove(shimPath)
}

// shimConsentRecorded reports whether the user opted into the PATH shim, by
// looking for the fenced marker installPathShim writes into a shell rc.
//
// The rc block — not the shim file — is the durable record of that choice. The
// shim lives in ~/.agentjail/bin, which uninstall removes wholesale
// (removeInstallDir), so the file's absence cannot distinguish "never opted in"
// from "opted in, then wiped by an uninstall/reinstall cycle". The rc block
// survives both. See ADR 0062.
func shimConsentRecorded(home string) bool {
	for _, rc := range shellRCCandidates(home) {
		b, err := os.ReadFile(rc)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), shimRCMarkerStart) {
			return true
		}
	}
	return false
}

// reassertPathShim regenerates the PATH shim whenever the user has opted in —
// either the shim is already on disk (refresh it, so a brew upgrade or curl|sh
// reinstall picks up the current template instead of stale flags from an older
// build), or consent is recorded in a shell rc but the file is gone (restore it).
//
// The restore case is the one that matters: without it, the rc still prepends
// ~/.agentjail/bin to PATH but no claude sits there, so the shell resolves
// straight past it to the real unshielded binary — silently, with no error and
// no missing-command. The user believes they are shielded and is not. Called
// unconditionally from install. See ADR 0062.
func reassertPathShim(home string) {
	shimPath := filepath.Join(home, ".agentjail", "bin", "claude")
	_, statErr := os.Stat(shimPath)
	onDisk := statErr == nil

	if !onDisk && !shimConsentRecorded(home) {
		return // never opted in — nothing to reassert
	}

	if err := installPathShim(home); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: warning: could not reassert PATH shim: %v\n", err)
		return
	}
	if !onDisk {
		fmt.Fprintln(os.Stderr, "agentjail: restored the PATH shim (your shell profile opts into it, but the shim was missing)")
	}
}

// addToShellProfile adds the agentjail bin directory to PATH in the
// appropriate shell profile. Idempotent — skips if already present.
func addToShellProfile(home, binDir string) error {
	block := fmt.Sprintf("\n%s\nexport PATH=\"%s:$PATH\"\n%s\n", shimRCMarkerStart, binDir, shimRCMarkerEnd)

	// Determine which rc file to use.
	rcPath := ""
	switch {
	case fileExists(filepath.Join(home, ".zshrc")):
		rcPath = filepath.Join(home, ".zshrc")
	case fileExists(filepath.Join(home, ".bashrc")):
		rcPath = filepath.Join(home, ".bashrc")
	case fileExists(filepath.Join(home, ".bash_profile")):
		rcPath = filepath.Join(home, ".bash_profile")
	default:
		// Create .bashrc as default.
		rcPath = filepath.Join(home, ".bashrc")
	}

	// Check if already present.
	content, _ := os.ReadFile(rcPath)
	if strings.Contains(string(content), shimRCMarkerStart) {
		return nil // already present
	}

	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(block)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "  PATH added to %s\n", rcPath)
	return nil
}

// isOurWrapper checks if a wrapper path belongs to agentjail.
func isOurWrapper(path, home string) bool {
	if path == "" {
		return false
	}
	agentjailDir := filepath.Join(home, ".agentjail")
	return strings.HasPrefix(path, agentjailDir)
}

// stripJSONComments removes single-line // comments and trailing commas
// from JSONC content. This is a simple implementation that handles the
// common cases in VS Code settings files.
func stripJSONComments(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Remove inline comments (after a string value).
		if idx := strings.Index(line, " //"); idx > 0 {
			// Only strip if it looks like a comment (not inside a string).
			beforeComment := line[:idx]
			quoteCount := strings.Count(beforeComment, "\"") - strings.Count(beforeComment, "\\\"")
			if quoteCount%2 == 0 {
				line = beforeComment
			}
		}
		out = append(out, line)
	}
	result := strings.Join(out, "\n")

	// Remove trailing commas before } or ].
	result = strings.ReplaceAll(result, ",\n}", "\n}")
	result = strings.ReplaceAll(result, ",\n]", "\n]")
	// Handle whitespace variations.
	result = strings.ReplaceAll(result, ",  \n}", "\n}")
	result = strings.ReplaceAll(result, ",\t\n}", "\n}")

	return []byte(result)
}

// fileExists is defined in install.go and shared across the package.

// vscodeSettingsPath is defined in cmd_doctor.go and shared here.
// Both files are in the same package so the function is directly accessible.
