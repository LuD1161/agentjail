package main

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/sshagent"
)

func TestSSHCommandPatternMatches(t *testing.T) {
	positive := []string{
		"git fetch origin",
		"ssh host",
		"scp a b",
		"rsync -e ssh -av src/ dest/",
		"git push",
		"git clone git@github.com:foo/bar.git",
		"sftp user@host",
		"git ls-remote origin",
	}
	for _, cmd := range positive {
		if !sshCommandPattern.MatchString(cmd) {
			t.Errorf("sshCommandPattern.MatchString(%q) = false, want true", cmd)
		}
	}
}

func TestSSHCommandPatternNonMatches(t *testing.T) {
	negative := []string{
		"ls -la",
		"npm install",
	}
	for _, cmd := range negative {
		if sshCommandPattern.MatchString(cmd) {
			t.Errorf("sshCommandPattern.MatchString(%q) = true, want false", cmd)
		}
	}
}

// unsetGetenv simulates a host env with no relevant variables set - used by
// tests that don't exercise the pinned-IdentityFile / git-marker logic.
func unsetGetenv(string) string { return "" }

// overrideSetGetenv simulates a host env where the shield has set the git
// auto-fix marker.
func overrideSetGetenv(key string) string {
	if key == agentjailSSHOverrideEnv {
		return "1"
	}
	return ""
}

// readyProbe simulates an ssh-agent that already has keys loaded.
func readyProbe(ctx context.Context) sshagent.Status {
	return sshagent.Status{Readiness: sshagent.ReadinessReady, KeysOnDisk: true, KeyPaths: []string{"/home/u/.ssh/id_ed25519"}}
}

// readyPinnedProbe simulates an ssh-agent that has keys loaded AND a pinned
// IdentityFile blind spot (config pins an on-disk file the shield blocks).
func readyPinnedProbe(ctx context.Context) sshagent.Status {
	return sshagent.Status{
		Readiness:           sshagent.ReadinessReady,
		KeysOnDisk:          true,
		KeyPaths:            []string{"/home/u/.ssh/id_ed25519"},
		PinnedIdentityPaths: []string{"/home/u/.ssh/id_ed25519"},
	}
}

// needsRemediationProbe simulates keys on disk but no agent reachable.
func needsRemediationProbe(ctx context.Context) sshagent.Status {
	return sshagent.Status{Readiness: sshagent.ReadinessNoAgent, KeysOnDisk: true, KeyPaths: []string{"/home/u/.ssh/id_ed25519"}}
}

// slowProbe respects ctx cancellation: it sleeps well past the 75ms probe
// timeout sshAdvisory enforces, then returns a zero Status if woken normally
// (which should never happen in this test) or via ctx.Done() (the expected
// path), simulating a hung ssh-agent probe that gets abandoned.
func slowProbe(ctx context.Context) sshagent.Status {
	select {
	case <-time.After(150 * time.Millisecond):
		return sshagent.Status{Readiness: sshagent.ReadinessNoAgent, KeysOnDisk: true, KeyPaths: []string{"/home/u/.ssh/id_ed25519"}}
	case <-ctx.Done():
		return sshagent.Status{}
	}
}

func TestSSHAdvisoryAllowMatchingNeedsRemediation(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	ppid := 12345

	if err := sshAdvisory(&buf, "Bash", "git push origin main", ppid, needsRemediationProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}

	if !strings.Contains(buf.String(), "ssh-add") {
		t.Errorf("advisory output = %q, want it to contain ssh-add remediation text", buf.String())
	}

	flagPath := sshAdvisorySentinelPath(dir, ppid)
	if _, err := os.Stat(flagPath); err != nil {
		t.Errorf("expected sentinel flag file at %s to exist: %v", flagPath, err)
	}
}

func TestSSHAdvisoryOneShotPerSession(t *testing.T) {
	dir := t.TempDir()
	ppid := 22222

	var first bytes.Buffer
	if err := sshAdvisory(&first, "Bash", "git push origin main", ppid, needsRemediationProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("first sshAdvisory returned error: %v", err)
	}
	if first.Len() == 0 {
		t.Fatalf("expected first call to write an advisory")
	}

	var second bytes.Buffer
	if err := sshAdvisory(&second, "Bash", "git push origin main", ppid, needsRemediationProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("second sshAdvisory returned error: %v", err)
	}
	if second.Len() != 0 {
		t.Errorf("expected second call (same ppid) to write nothing, got %q", second.String())
	}
}

func TestSSHAdvisoryNonMatchingCommand(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := sshAdvisory(&buf, "Bash", "npm install", 33333, needsRemediationProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for non-matching command, got %q", buf.String())
	}

	// No probe should have been invoked, so no flag file should exist either.
	flagPath := sshAdvisorySentinelPath(dir, 33333)
	if _, err := os.Stat(flagPath); err == nil {
		t.Errorf("expected no sentinel flag file for non-matching command, found one at %s", flagPath)
	}
}

func TestSSHAdvisoryNonBashTool(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := sshAdvisory(&buf, "Read", "ssh host", 44444, needsRemediationProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for non-Bash tool, got %q", buf.String())
	}
}

func TestSSHAdvisoryProbeReady(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := sshAdvisory(&buf, "Bash", "ssh host", 55555, readyProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output when agent is ready, got %q", buf.String())
	}
}

func TestSSHAdvisoryProbeTimeout(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	start := time.Now()
	if err := sshAdvisory(&buf, "Bash", "ssh host", 66666, slowProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	elapsed := time.Since(start)

	if buf.Len() != 0 {
		t.Errorf("expected no output when probe is abandoned at timeout, got %q", buf.String())
	}
	// The probe itself must be bounded near sshAdvisoryProbeTimeout, not the
	// full 150ms the stub would otherwise sleep for.
	if elapsed >= 150*time.Millisecond {
		t.Errorf("sshAdvisory took %v, want it bounded near the %v probe timeout", elapsed, sshAdvisoryProbeTimeout)
	}
}

func TestSSHAdvisoryNeverReturnsErrorThatWouldAlterHookFlow(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	cases := []struct {
		toolName string
		command  string
		probe    func(context.Context) sshagent.Status
	}{
		{"Bash", "ssh host", readyProbe},
		{"Bash", "git push", needsRemediationProbe},
		{"Bash", "ls -la", needsRemediationProbe},
		{"Read", "ssh host", needsRemediationProbe},
	}
	for i, c := range cases {
		if err := sshAdvisory(&buf, c.toolName, c.command, 70000+i, c.probe, "darwin", dir, unsetGetenv); err != nil {
			t.Errorf("case %d: sshAdvisory returned non-nil error %v; the hook must never see an error here", i, err)
		}
	}
}

func TestSSHAdvisorySentinelPath(t *testing.T) {
	got := sshAdvisorySentinelPath("/tmp", 999)
	want := "/tmp/agentjail-ssh-warned-" + strconv.Itoa(999)
	if got != want {
		t.Errorf("sshAdvisorySentinelPath(/tmp, 999) = %q, want %q", got, want)
	}
}

func TestSSHAdvisoryPinnedDirectSSH(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	ppid := 80001

	if err := sshAdvisory(&buf, "Bash", "ssh host", ppid, readyPinnedProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "IdentityFile=none") {
		t.Errorf("advisory output = %q, want it to contain the pinned-IdentityFile remediation", buf.String())
	}

	pinnedPath := sshPinnedSentinelPath(dir, ppid)
	if _, err := os.Stat(pinnedPath); err != nil {
		t.Errorf("expected pinned sentinel at %s to exist: %v", pinnedPath, err)
	}

	// Second call for the same ppid must stay silent (one-shot).
	var second bytes.Buffer
	if err := sshAdvisory(&second, "Bash", "ssh host", ppid, readyPinnedProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("second sshAdvisory returned error: %v", err)
	}
	if second.Len() != 0 {
		t.Errorf("expected second call (same ppid) to write nothing, got %q", second.String())
	}
}

func TestSSHAdvisoryPinnedGitSuppressedWhenOverrideSet(t *testing.T) {
	dir := t.TempDir()
	ppid := 80002

	var buf bytes.Buffer
	if err := sshAdvisory(&buf, "Bash", "git clone git@github.com:foo/bar.git", ppid, readyPinnedProbe, "linux", dir, overrideSetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for git command when shield auto-handled it, got %q", buf.String())
	}

	pinnedPath := sshPinnedSentinelPath(dir, ppid)
	if _, err := os.Stat(pinnedPath); err == nil {
		t.Errorf("expected no pinned sentinel to be created for a suppressed-git occurrence, found one at %s", pinnedPath)
	}

	// A subsequent direct ssh command in the same session must still warn -
	// proving the suppressed git occurrence did not consume the sentinel.
	var second bytes.Buffer
	if err := sshAdvisory(&second, "Bash", "ssh host", ppid, readyPinnedProbe, "linux", dir, overrideSetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if !strings.Contains(second.String(), "IdentityFile=none") {
		t.Errorf("expected direct ssh to still print the pinned advisory, got %q", second.String())
	}
}

func TestSSHAdvisoryPinnedGitPrintsWhenOverrideUnset(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := sshAdvisory(&buf, "Bash", "git clone git@github.com:foo/bar.git", 80003, readyPinnedProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "IdentityFile=none") {
		t.Errorf("expected pinned advisory for git when the override marker is unset (opt-out path), got %q", buf.String())
	}
}

func TestSSHAdvisoryNotPinnedReadyStaysSilent(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := sshAdvisory(&buf, "Bash", "ssh host", 80004, readyProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for a ready, non-pinned status, got %q", buf.String())
	}
}

func TestSSHAdvisoryEmptyAgentStillFiresRegression(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := sshAdvisory(&buf, "Bash", "ssh host", 80005, needsRemediationProbe, "linux", dir, unsetGetenv); err != nil {
		t.Fatalf("sshAdvisory returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "ssh-add") {
		t.Errorf("expected the existing empty-agent advisory to still fire, got %q", buf.String())
	}
}

func TestSSHAdvisoryPinnedSentinelPath(t *testing.T) {
	got := sshPinnedSentinelPath("/tmp", 999)
	want := "/tmp/agentjail-ssh-pinned-warned-" + strconv.Itoa(999)
	if got != want {
		t.Errorf("sshPinnedSentinelPath(/tmp, 999) = %q, want %q", got, want)
	}
}
