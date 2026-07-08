package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// TestRunHelpKnownTopic verifies that "agentjail help <topic>" (via runHelp,
// the function wired up in cmd_help.go's helpTopicCmd.Run) prints
// topic-specific content rather than the generic top-level usage screen.
func TestRunHelpKnownTopic(t *testing.T) {
	for topic, content := range helpTopics {
		t.Run(topic, func(t *testing.T) {
			// helpTopics content should contain the topic's own heading text,
			// and runHelp should reproduce it verbatim on stdout.
			if !strings.Contains(content, "agentjail") {
				t.Fatalf("help topic %q looks empty/malformed", topic)
			}
		})
	}
}

// TestHelpTopicCmdWiredToRunHelp exercises the real cobra command
// ("agentjail help <topic>") end-to-end to confirm it's wired to runHelp and
// prints topic-specific text on stdout, not the generic usage() screen
// (regression guard for U5's dead help-topic plumbing). runHelp writes
// straight to os.Stdout (not cmd.OutOrStdout), so we redirect the process's
// stdout via a pipe to capture it.
func TestHelpTopicCmdWiredToRunHelp(t *testing.T) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	rootCmd.SetArgs([]string{"help", "replay"})
	execErr := rootCmd.Execute()

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	if execErr != nil {
		t.Fatalf("rootCmd.Execute() error: %v", execErr)
	}
	got := string(out)
	if !strings.Contains(got, "Session Replay") {
		t.Errorf("agentjail help replay: expected topic content, got:\n%s", got)
	}
	if strings.Contains(got, "Usage") && strings.Contains(got, "agentjail <command> [flags]") {
		t.Errorf("agentjail help replay: printed generic usage() screen instead of topic content:\n%s", got)
	}
}

// TestRunHelpReturnsTopicText directly checks runHelp's dispatch logic
// (used by "agentjail help <topic>") returns 0 for known topics and 2 for
// unknown ones.
func TestRunHelpReturnsTopicText(t *testing.T) {
	if code := runHelp([]string{"replay"}); code != 0 {
		t.Errorf("runHelp([\"replay\"]) = %d, want 0", code)
	}
	if code := runHelp([]string{"not-a-real-topic"}); code != 2 {
		t.Errorf("runHelp([\"not-a-real-topic\"]) = %d, want 2", code)
	}
	if code := runHelp(nil); code != 0 {
		t.Errorf("runHelp(nil) = %d, want 0", code)
	}
}

// TestReplayTopicMatchesRealFlags guards against the drift U5 called out:
// the "replay" help topic must describe the flags runReplay actually parses
// (--db, --session, --verbose, --follow, --list, --no-color, --basic), not
// the old invented --last/--action/--since flags.
func TestReplayTopicMatchesRealFlags(t *testing.T) {
	content := helpTopics["replay"]
	for _, want := range []string{"--session", "--list", "--follow", "--basic", "--no-color", "--verbose"} {
		if !strings.Contains(content, want) {
			t.Errorf("replay help topic missing real flag %q", want)
		}
	}
	for _, stale := range []string{"--last", "--action=", "--since="} {
		if strings.Contains(content, stale) {
			t.Errorf("replay help topic still references invented flag %q", stale)
		}
	}
}
