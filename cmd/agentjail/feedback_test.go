package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFeedbackMessage_JoinsArgs(t *testing.T) {
	if got := feedbackMessage([]string{"too", "many", "denies"}); got != "too many denies" {
		t.Fatalf("got %q", got)
	}
}

func TestRunFeedback_NoBackendPrintsIssueLink(t *testing.T) {
	// In tests the telemetry backend is empty → SendFeedback returns ErrNoBackend,
	// so runFeedbackWith must print the GitHub issue URL and exit 0.
	var out bytes.Buffer
	code := runFeedbackWith([]string{"hello"}, "", &out, strings.NewReader("\n"))
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "github.com/LuD1161/agentjail/issues") {
		t.Fatalf("expected issue link fallback, got %q", out.String())
	}
}
