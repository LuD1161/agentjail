package main

import (
	"strings"
	"testing"
)

func TestRunHelpGettingStarted(t *testing.T) {
	stdout, stderr, code := captureOutput(t, func() int {
		return runHelp([]string{"getting-started"})
	})
	if code != 0 || stderr != "" {
		t.Fatalf("runHelp(getting-started) code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "Getting Started with agentjail") || !strings.Contains(stdout, "agentjail sessions") {
		t.Fatalf("getting-started guide is incomplete:\n%s", stdout)
	}
}

func TestRunHelpUsesCommandTree(t *testing.T) {
	stdout, stderr, code := captureOutput(t, func() int {
		return runHelp([]string{"replay"})
	})
	if code != 0 || stderr != "" {
		t.Fatalf("runHelp(replay) code=%d stderr=%q", code, stderr)
	}
	for _, want := range []string{"Replay recorded decisions", "agentjail replay", "--session"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("command help missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunHelpLegacyAliasUsesCanonicalCommand(t *testing.T) {
	stdout, _, code := captureOutput(t, func() int {
		return runHelp([]string{"mcp-tools"})
	})
	if code != 0 || !strings.Contains(stdout, "agentjail mcp tool") {
		t.Fatalf("legacy help alias code=%d output=%q", code, stdout)
	}
}

func TestRunHelpUnknownAndIndex(t *testing.T) {
	_, _, code := captureOutput(t, func() int {
		return runHelp([]string{"not-a-real-command"})
	})
	if code != 2 {
		t.Fatalf("unknown help code=%d, want 2", code)
	}
	stdout, _, code := captureOutput(t, func() int { return runHelp(nil) })
	if code != 0 || !strings.Contains(stdout, "getting-started") {
		t.Fatalf("help index code=%d output=%q", code, stdout)
	}
}
