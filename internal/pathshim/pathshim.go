// Package pathshim owns the opt-in shell wrappers for supported agent CLIs.
// See ADR 0062-path-shim-consent-is-the-rc-block.
package pathshim

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	MarkerStart = "# >>> agentjail >>>"
	MarkerEnd   = "# <<< agentjail <<<"
)

// Target identifies one CLI wrapped by the shared PATH-shim contract.
type Target struct {
	Command     string
	DisplayName string
}

var targets = []Target{
	{Command: "claude", DisplayName: "Claude Code"},
	{Command: "codex", DisplayName: "Codex"},
	{Command: "agent", DisplayName: "Cursor"},
}

// Targets returns a copy of the supported shim targets.
func Targets() []Target {
	return append([]Target(nil), targets...)
}

// Result describes whether Reassert acted and repaired an incomplete set.
type Result struct {
	Applied  bool
	Restored bool
}

// Install writes every supported shim and records consent in a shell profile.
func Install(home, shieldBin string, stdout, stderr io.Writer) error {
	if info, err := os.Stat(shieldBin); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("shield binary not executable at %s", shieldBin)
	}

	shimDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("create shim directory: %w", err)
	}

	for _, target := range targets {
		shimPath := filepath.Join(shimDir, target.Command)
		if err := os.WriteFile(shimPath, []byte(Render(target, shieldBin, shimDir, shimPath)), 0o755); err != nil {
			return fmt.Errorf("write %s shim: %w", target.Command, err)
		}
		fmt.Fprintf(stdout, "  %s PATH shim installed at %s\n", target.DisplayName, shimPath)
	}

	if err := AddToShellProfile(home, shimDir); err != nil {
		fmt.Fprintf(stderr, "  warning: could not update shell profile: %v\n", err)
		fmt.Fprintf(stderr, "  Add this to your shell profile manually:\n")
		fmt.Fprintf(stderr, "    export PATH=\"%s:$PATH\"\n", shimDir)
	}
	fmt.Fprintln(stdout, "  Run `hash -r` or open a new shell to activate.")
	return nil
}

// Reassert refreshes shims only when a file or durable consent marker exists.
func Reassert(home, shieldBin string, stdout, stderr io.Writer) (Result, error) {
	complete := Complete(home)
	if !AnyInstalled(home) && !ConsentRecorded(home, os.Getenv("ZDOTDIR")) {
		return Result{}, nil
	}
	if err := Install(home, shieldBin, stdout, stderr); err != nil {
		return Result{}, err
	}
	return Result{Applied: true, Restored: !complete}, nil
}

// Remove deletes every supported shim without changing shell consent.
func Remove(home string) {
	for _, target := range targets {
		_ = os.Remove(filepath.Join(home, ".agentjail", "bin", target.Command))
	}
}

// Complete reports whether every supported shim exists.
func Complete(home string) bool {
	for _, target := range targets {
		if _, err := os.Stat(filepath.Join(home, ".agentjail", "bin", target.Command)); err != nil {
			return false
		}
	}
	return true
}

// AnyInstalled reports whether at least one supported shim exists.
func AnyInstalled(home string) bool {
	for _, target := range targets {
		if _, err := os.Stat(filepath.Join(home, ".agentjail", "bin", target.Command)); err == nil {
			return true
		}
	}
	return false
}

// ConsentRecorded reads the durable shell-profile marker. See ADR 0062-path-shim-consent-is-the-rc-block.
func ConsentRecorded(home, zdotdir string) bool {
	for _, rc := range RCCandidates(home, zdotdir) {
		b, err := os.ReadFile(rc)
		if err == nil && strings.Contains(string(b), MarkerStart) {
			return true
		}
	}
	return false
}

// RCCandidates lists every profile AgentJail may write or inspect.
func RCCandidates(home, zdotdir string) []string {
	candidates := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	}
	if zdotdir != "" {
		candidates = append(candidates, filepath.Join(zdotdir, ".zshrc"))
	}
	return candidates
}

// AddToShellProfile records consent and prepends the shim directory.
func AddToShellProfile(home, binDir string) error {
	block := fmt.Sprintf("\n%s\nexport PATH=\"%s:$PATH\"\n%s\n", MarkerStart, binDir, MarkerEnd)

	rcPath := filepath.Join(home, ".bashrc")
	for _, candidate := range []string{".zshrc", ".bashrc", ".bash_profile"} {
		path := filepath.Join(home, candidate)
		if _, err := os.Stat(path); err == nil {
			rcPath = path
			break
		}
	}

	content, _ := os.ReadFile(rcPath)
	if strings.Contains(string(content), MarkerStart) {
		return nil
	}
	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return err
	}
	return nil
}

// Render produces one fail-open wrapper. See ADR 0063-shim-fails-open-uninstall-is-total.
func Render(target Target, shieldBin, shimDir, shimPath string) string {
	commandUpper := strings.ToUpper(target.Command)
	launcherBin := filepath.Join(filepath.Dir(shieldBin), "agentjail")
	codexApprovalCompat := ""
	if target.Command == "codex" {
		codexApprovalCompat = `# Keep Codex unsandboxed while preserving AgentJail's exact execpolicy prompt.
# See ADR 0118-codex-approval-broker.
if [ "${1:-}" = "--yolo" ] || [ "${1:-}" = "--dangerously-bypass-approvals-and-sandbox" ]; then
    shift
    set -- \
        --sandbox danger-full-access \
        -c 'approval_policy={ granular = { sandbox_approval = false, rules = true, mcp_elicitations = false, request_permissions = false, skill_approval = false } }' \
        -c 'approvals_reviewer="user"' \
        "$@"
fi

`
	}
	return fmt.Sprintf(`#!/bin/sh
# agentjail PATH shim for %s.
# Installed by: agentjail install --with-path-shim
# Remove with:  agentjail uninstall

set -e

SHIELD="%s"
LAUNCHER="%s"

find_real_agent() {
    _orig_path="$PATH"
    _shim_dir="%s"
    PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "^${_shim_dir}$" | tr '\n' ':' | sed 's/:$//')
    _real=$(command -v %s 2>/dev/null || true)
    PATH="$_orig_path"
    echo "$_real"
}

REAL_%s=$(find_real_agent)

if [ -z "$REAL_%s" ]; then
    echo "ERROR: %s not found in PATH (excluding %s)" >&2
    echo "  Install %s, or remove the shim: rm %s" >&2
    exit 127
fi

if [ "$REAL_%s" = "%s" ]; then
    echo "ERROR: PATH shim resolved to itself at %s" >&2
    echo "  Check your PATH order." >&2
    exit 1
fi

%s

# Missing enforcement must stay loud without breaking the underlying CLI.
# See ADR 0063-shim-fails-open-uninstall-is-total.
if [ ! -x "$SHIELD" ]; then
    echo "WARNING: agentjail-shield is missing or not executable at $SHIELD" >&2
    echo "  Running %s UNSHIELDED — policy hooks may still apply." >&2
    echo "  Repair: agentjail install --with-path-shim   |   Remove shim: agentjail uninstall --path-shim-only (or rm %s)" >&2
    exec "$REAL_%s" "$@"
fi

if [ -x "$LAUNCHER" ]; then
    exec "$LAUNCHER" run --tunnel -- %s "$@"
fi

echo "WARNING: agentjail launcher is missing or not executable at $LAUNCHER" >&2
echo "  Git-over-SSH setup is unavailable; entering the shield directly." >&2
exec "$SHIELD" --tunnel -- "$REAL_%s" "$@"

`, target.Command, shieldBin, launcherBin, shimDir, target.Command, commandUpper, commandUpper,
		target.Command, shimDir, target.DisplayName, shimPath, commandUpper, shimPath,
		shimPath, codexApprovalCompat, target.Command, shimPath, commandUpper, target.Command, commandUpper)
}
