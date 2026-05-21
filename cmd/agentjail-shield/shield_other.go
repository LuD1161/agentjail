//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
	"syscall"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// runShield is the fallback implementation for platforms other than macOS and
// Linux (e.g. Windows, FreeBSD).
//
// It prints a loud warning and execs the agent without any sandbox.
// The hook layer (agentjail-hook) still runs on every PreToolUse call.
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, policyPath string) {
	if profilePrint {
		fmt.Fprintln(os.Stderr, "agentjail-shield: sandbox is not supported on this platform.")
		fmt.Fprintln(os.Stderr, "Supported platforms: darwin (macOS), linux (Landlock, kernel 5.13+)")
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr,
		"agentjail-shield WARNING: OS-native sandbox is not supported on this platform.")
	fmt.Fprintln(os.Stderr,
		"  Supported platforms: macOS (sandbox-exec) and Linux (Landlock, kernel 5.13+)")
	fmt.Fprintln(os.Stderr,
		"  Running agent WITHOUT sandbox.  The hook layer still enforces on every PreToolUse.")

	// Suppress unused-variable warnings: cfg, noNetproxy, and policyPath are
	// not used on unsupported platforms.
	_ = cfg
	_ = noNetproxy
	_ = policyPath

	argv := append([]string{agentPath}, agentArgs...)
	if err := syscall.Exec(agentPath, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: exec agent failed: %v\n", err)
		os.Exit(1)
	}
}
