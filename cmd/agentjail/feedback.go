package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

const feedbackIssueURL = "https://github.com/LuD1161/agentjail/issues/new"

// runFeedback is the `agentjail feedback [message...]` entry point.
func runFeedback(args []string) int {
	return runFeedbackWith(args, "", os.Stdout, os.Stdin)
}

// feedbackMessage joins positional args into a single message string.
func feedbackMessage(args []string) string {
	return strings.TrimSpace(strings.Join(args, " "))
}

// runFeedbackWith is the testable core. contactOverride is "" in production
// (prompted from in); tests pass an empty reader to skip the contact prompt.
func runFeedbackWith(args []string, contactOverride string, out io.Writer, in io.Reader) int {
	r := bufio.NewReader(in)

	msg := feedbackMessage(args)
	if msg == "" {
		fmt.Fprint(out, "Your feedback (one line): ")
		line, _ := r.ReadString('\n')
		msg = strings.TrimSpace(line)
	}
	if msg == "" {
		fmt.Fprintln(out, "No message provided; nothing sent.")
		return 0
	}

	contact := contactOverride
	if contact == "" {
		fmt.Fprint(out, "Contact for follow-up (optional, press Enter to skip): ")
		line, _ := r.ReadString('\n')
		contact = strings.TrimSpace(line)
	}

	fmt.Fprintln(out, "Sending your feedback (message + agentjail version + OS, tied to a random ID)...")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	err := telemetry.SendFeedback(ctx, mustPaths(), os.Getenv, version, runtime.GOOS, msg, contact)
	switch {
	case err == nil:
		fmt.Fprintln(out, "Thanks — your feedback was sent.")
		return 0
	case err == telemetry.ErrNoBackend:
		fmt.Fprintf(out, "This build has no telemetry backend, so feedback can't be sent directly.\nPlease open an issue instead: %s\n", feedbackIssueURL)
		return 0
	default:
		fmt.Fprintf(out, "Couldn't send feedback (%v).\nPlease open an issue instead: %s\n", err, feedbackIssueURL)
		return 0
	}
}

// mustPaths returns telemetry paths, falling back to a zero Paths on error (the
// send will then fail gracefully to the issue-link path).
func mustPaths() telemetry.Paths {
	p, err := telemetry.DefaultPaths()
	if err != nil {
		return telemetry.Paths{}
	}
	return p
}
