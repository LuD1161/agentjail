package main

import (
	"fmt"
	"os"
	"strconv"
)

// shieldWarningFlagPath returns the path to the one-shot warning flag file
// for this agent session. Keyed on the parent PID so each Claude session
// gets the warning exactly once.
func shieldWarningFlagPath() string {
	return "/tmp/agentjail-shield-warned-" + strconv.Itoa(os.Getppid())
}

// checkShieldStatus returns true if the current process appears to be running
// under the agentjail shield. Detection heuristics:
//   - HTTPS_PROXY=http://127.0.0.1:9100 (shield's netproxy)
//   - NoNewPrivs: 1 in /proc/self/status (Landlock requirement, Linux only)
func checkShieldStatus() bool {
	// Check 1: the shield's network proxy env var.
	if os.Getenv("HTTPS_PROXY") == "http://127.0.0.1:9100" {
		return true
	}

	// Check 2: platform-specific (Landlock NoNewPrivs on Linux).
	return checkNoNewPrivs()
}

// maybeEmitShieldWarning checks whether the session is shielded and, if not,
// emits a one-time informational warning to stderr. The warning is gated by a
// flag file so it fires only on the first tool call per agent session.
//
// This function is non-blocking: it never changes the allow/deny decision.
func maybeEmitShieldWarning() {
	flagPath := shieldWarningFlagPath()

	// Already warned this session? Skip.
	if _, err := os.Stat(flagPath); err == nil {
		return
	}

	// Running under shield? No warning needed.
	if checkShieldStatus() {
		return
	}

	// Create the flag file first so concurrent hook invocations don't
	// duplicate the warning.
	_ = os.WriteFile(flagPath, []byte("1"), 0o600)

	// Respect NO_COLOR (https://no-color.org/).
	noColor := os.Getenv("NO_COLOR") != ""
	emitShieldWarning(noColor)
}

// emitShieldWarning writes the shield warning banner to stderr.
func emitShieldWarning(noColor bool) {
	// ANSI escape helpers — empty when NO_COLOR is set.
	var boldYellow, bold, cyan, reset string
	if !noColor {
		boldYellow = "\033[1;33m"
		bold = "\033[1m"
		cyan = "\033[36m"
		reset = "\033[0m"
	}

	fmt.Fprintf(os.Stderr,
		"\n%s⚠  agentjail: this session is not running under shield%s\n"+
			"\n"+
			"   Credential paths are not kernel-protected.\n"+
			"   Shell obfuscation bypasses (variable indirection, interpreter\n"+
			"   escapes, symlinks) may access sensitive files.\n"+
			"\n"+
			"   %sFor full protection:%s\n"+
			"     Terminal:  %sagentjail run -- <agent>%s\n"+
			"     VS Code:   %sagentjail install --for vscode%s\n"+
			"     Cursor:    %sagentjail install --for cursor-ide%s\n"+
			"\n"+
			"   Run %sagentjail doctor%s for setup details.\n\n",
		boldYellow, reset,
		bold, reset,
		cyan, reset,
		cyan, reset,
		cyan, reset,
		cyan, reset,
	)
}
