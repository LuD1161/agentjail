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

// sshDirectPattern matches only the direct ssh/scp/sftp/rsync clause of
// sshCommandPattern (not git). Used to distinguish "direct ssh-ish command"
// from "git command that may go over ssh" for the pinned-IdentityFile
// advisory, which applies unconditionally to the former but only
// conditionally (based on the shield's auto-fix marker) to the latter.
var sshDirectPattern = regexp.MustCompile(`\b(ssh|scp|sftp|rsync)\b`)

// sshGitPattern matches only the git clause of sshCommandPattern.
var sshGitPattern = regexp.MustCompile(`\bgit\b.*\b(clone|fetch|pull|push|ls-remote)\b`)

// agentjailSSHOverrideEnv is the marker the shield sets (to "1") when it
// auto-injects an agent-backed GIT_SSH_COMMAND for git, meaning git already
// routes auth through the agent and the pinned-IdentityFile advisory would
// be redundant noise for that invocation.
const agentjailSSHOverrideEnv = "AGENTJAIL_SSH_OVERRIDE"

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
	_ = sshAdvisory(os.Stderr, toolName, command, os.Getppid(), sshagent.Probe, runtime.GOOS, sshAdvisoryFlagDir, os.Getenv)
}

// sshAdvisorySentinelPath returns the one-shot flag file path for the
// empty-agent (NeedsRemediation) advisory for this agent session, keyed on
// ppid - mirrors shieldWarningFlagPath's keying scheme so concurrent hook
// invocations within the same session dedupe consistently.
func sshAdvisorySentinelPath(flagDir string, ppid int) string {
	return filepath.Join(flagDir, "agentjail-ssh-warned-"+strconv.Itoa(ppid))
}

// sshPinnedSentinelPath returns the one-shot flag file path for the
// pinned-IdentityFile blind-spot advisory for this agent session. It is a
// separate sentinel from sshAdvisorySentinelPath so the two advisories fire
// independently of each other - NeedsRemediation and PinnedBlindSpot are
// mutually exclusive per probe, but across a session either could occur
// first without suppressing the other.
func sshPinnedSentinelPath(flagDir string, ppid int) string {
	return filepath.Join(flagDir, "agentjail-ssh-pinned-warned-"+strconv.Itoa(ppid))
}

// sshAdvisory is the testable core of the ssh-agent advisory. It covers two
// independent, mutually-exclusive-per-probe advisories:
//
//   - the empty-agent advisory (existing): keys on disk, agent not ready.
//   - the pinned-IdentityFile blind spot (new): agent IS ready, but the
//     user's ssh config pins an on-disk IdentityFile the shield blocks, so
//     ssh reads that file first and fails before ever trying the agent.
//
//  1. Gates on tool name ("Bash") and an ssh-using command pattern; returns
//     immediately (no probe) on any non-match.
//  2. Classifies the command as direct ssh-ish (ssh/scp/sftp/rsync) and/or
//     git, and determines which of the two advisories are still possible
//     given their one-shot sentinels and (for the pinned advisory) whether
//     it applies to this command at all. If neither is possible, returns
//     without probing.
//  3. Probes ssh-agent readiness once, under a hard timeout via the injected
//     probe func - a slow/hung probe is abandoned silently.
//  4. Creates the relevant sentinel (O_EXCL) and writes a concise banner to
//     w only if that advisory's condition is met. A sentinel is created
//     ONLY when its advisory is actually printed - a suppressed-git
//     occurrence never consumes the pinned sentinel.
//
// The return value is diagnostic-only (always nil in current callers); the
// function never alters caller control flow, and never writes anything
// other than the advisory text to w - callers wire w to os.Stderr, never
// os.Stdout, since stdout carries the hook's JSON decision.
func sshAdvisory(w io.Writer, toolName, command string, ppid int, probe func(context.Context) sshagent.Status, goos string, flagDir string, getenv func(string) string) error {
	if toolName != "Bash" {
		return nil
	}
	if !sshCommandPattern.MatchString(command) {
		return nil
	}

	isDirectSSH := sshDirectPattern.MatchString(command)
	isGit := sshGitPattern.MatchString(command)

	emptySentinelPath := sshAdvisorySentinelPath(flagDir, ppid)
	emptyPossible := !sentinelExists(emptySentinelPath)

	// git is suppressed only when the shield actually auto-handled it (the
	// marker is exactly "1"); a direct ssh-ish command always applies,
	// taking precedence even if the command also happens to match git.
	pinnedApplicable := isDirectSSH || (isGit && getenv(agentjailSSHOverrideEnv) != "1")
	pinnedSentinelPath := sshPinnedSentinelPath(flagDir, ppid)
	pinnedPossible := pinnedApplicable && !sentinelExists(pinnedSentinelPath)

	if !emptyPossible && !pinnedPossible {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshAdvisoryProbeTimeout)
	defer cancel()
	st := probe(ctx)

	switch {
	case st.NeedsRemediation() && emptyPossible:
		if !createSentinel(emptySentinelPath) {
			return nil
		}
		fmt.Fprintf(w,
			"\nagentjail: ssh keys found but not loaded in ssh-agent - the sandbox blocks\n"+
				"private-key reads, so ssh will fail. Fix: %s\n\n",
			st.Remediation(goos),
		)
	case st.PinnedBlindSpot() && pinnedPossible:
		if !createSentinel(pinnedSentinelPath) {
			return nil
		}
		note := ""
		if isGit {
			note = " (git is auto-handled by the shield unless AGENTJAIL_NO_SSH_OVERRIDE is set)"
		}
		fmt.Fprintf(w,
			"\nagentjail: ssh-agent has a key loaded, but your ssh config pins an\n"+
				"IdentityFile the sandbox blocks - ssh reads that file first and fails\n"+
				"before falling back to the agent%s. Fix: %s\n\n",
			note,
			st.PinnedRemediation(goos),
		)
	}
	return nil
}

// sentinelExists reports whether a one-shot sentinel file already exists at
// path, without creating it.
func sentinelExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// createSentinel atomically creates a one-shot sentinel file at path,
// returning true only if this call created it (false if it already existed
// or some other best-effort failure occurred, e.g. an unwritable sentinel
// dir - either way, the caller stays silent).
func createSentinel(path string) bool {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
