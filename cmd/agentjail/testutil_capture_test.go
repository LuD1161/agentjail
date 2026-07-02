package main

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// captureOutput redirects os.Stdout and os.Stderr for the duration of fn and
// returns everything each stream received. Several Phase 3 grant commands
// (cmd_allow.go, cmd_grants.go) write directly to os.Stdout/os.Stderr rather
// than an injected writer (matching the existing mcp.go/sessions.go style),
// so tests capture at the os.Std{out,err} level instead.
func captureOutput(t *testing.T, fn func() int) (stdout, stderr string, code int) {
	t.Helper()

	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
	}()

	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, outR)
		outCh <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, errR)
		errCh <- buf.String()
	}()

	code = fn()

	_ = outW.Close()
	_ = errW.Close()
	stdout = <-outCh
	stderr = <-errCh
	return stdout, stderr, code
}
