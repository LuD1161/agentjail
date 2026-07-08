package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/sshagent"
)

// sshCommandPattern matches shell commands that plausibly rely on
// ssh-agent-backed authentication: direct ssh/scp/sftp/rsync invocations, or
// a git remote subcommand (clone/fetch/pull/push/ls-remote) that may go over
// ssh. Compiled once at package init, never per call. False positives (e.g.
// "echo ssh is great") are acceptable - worst case is one extra, cheap,
// timeout-bounded probe.
var sshCommandPattern = regexp.MustCompile(`\b(ssh|scp|sftp|rsync)\b|\bgit\b.*\b(clone|fetch|pull|push|ls-remote)\b`)

// sshAdvisoryProbeTimeout bounds the ssh-agent probe so a hung or slow agent
// never adds latency to the hook's allow/deny decision path. A probe that
// doesn't return within this window is treated as "no remediation needed" -
// silent, not a false positive.
const sshAdvisoryProbeTimeout = 75 * time.Millisecond

// sshAdvisoryFlagDir is the sentinel directory used in production.
const sshAdvisoryFlagDir = "/tmp"

// maybeEmitSSHAgentWarning is the production entry point. It must be called
// AFTER the daemon's decision has been resolved and ONLY on the allow path -
// never on deny or ask - so a blocked ssh-ish command produces no
// remediation noise. It is non-blocking and never alters the hook's exit
// code or stdout output: any advisory text goes to stderr only, and errors
// are swallowed (best-effort).
func maybeEmitSSHAgentWarning(toolName string, toolInput map[string]interface{}) {
	command, _ := toolInput["command"].(string)
	_ = sshAdvisory(os.Stderr, toolName, command, os.Getppid(), sshagent.Probe, runtime.GOOS, sshAdvisoryFlagDir)
}

// sshAdvisorySentinelPath returns the one-shot flag file path for this agent
// session, keyed on ppid - mirrors shieldWarningFlagPath's keying scheme so
// concurrent hook invocations within the same session dedupe consistently.
func sshAdvisorySentinelPath(flagDir string, ppid int) string {
	return filepath.Join(flagDir, "agentjail-ssh-warned-"+strconv.Itoa(ppid))
}

// sshAdvisory is the testable core of the ssh-agent advisory.
//
//  1. Gates on tool name ("Bash") and an ssh-using command pattern; returns
//     immediately (no probe) on any non-match.
//  2. Enforces one-shot-per-session via an O_EXCL sentinel file, created
//     BEFORE probing so concurrent hook invocations can't double-warn or
//     double-probe.
//  3. Probes ssh-agent readiness under a hard timeout via the injected probe
//     func - a slow/hung probe is abandoned silently.
//  4. Writes a concise remediation banner to w only if remediation is
//     needed.
//
// The return value is diagnostic-only (always nil in current callers); the
// function never alters caller control flow, and never writes anything
// other than the advisory text to w - callers wire w to os.Stderr, never
// os.Stdout, since stdout carries the hook's JSON decision.
func sshAdvisory(w io.Writer, toolName, command string, ppid int, probe func(context.Context) sshagent.Status, goos string, flagDir string) error {
	if toolName != "Bash" {
		return nil
	}
	if !sshCommandPattern.MatchString(command) {
		return nil
	}

	flagPath := sshAdvisorySentinelPath(flagDir, ppid)
	f, err := os.OpenFile(flagPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		// Already warned this session (os.IsExist) or some other best-effort
		// failure (e.g. unwritable sentinel dir) - either way, stay silent.
		return nil
	}
	_ = f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sshAdvisoryProbeTimeout)
	defer cancel()
	st := probe(ctx)

	if !st.NeedsRemediation() {
		return nil
	}

	fmt.Fprintf(w,
		"\nagentjail: ssh keys found but not loaded in ssh-agent - the sandbox blocks\n"+
			"private-key reads, so ssh will fail. Fix: %s\n\n",
		st.Remediation(goos),
	)
	return nil
}
