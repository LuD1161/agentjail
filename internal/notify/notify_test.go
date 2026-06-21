package notify

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestSend_ConstructsOsascriptCommand(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	var capturedName string
	var capturedArgs []string

	orig := commandBuilder
	defer func() { commandBuilder = orig }()

	commandBuilder = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedName = name
		capturedArgs = args
		// Return a no-op command that will succeed
		return exec.CommandContext(ctx, "true")
	}

	err := Send(context.Background(), "Test Title", "Test Message")
	if err != nil {
		t.Fatalf("Send returned unexpected error: %v", err)
	}

	// Verify first arg is "osascript"
	if capturedName != "osascript" {
		t.Errorf("expected command %q, got %q", "osascript", capturedName)
	}

	// args to commandBuilder are: "-e", script, title, message
	if len(capturedArgs) < 4 {
		t.Fatalf("expected at least 4 args, got %d: %v", len(capturedArgs), capturedArgs)
	}

	if capturedArgs[0] != "-e" {
		t.Errorf("expected first arg %q, got %q", "-e", capturedArgs[0])
	}

	// Verify script contains "on run argv"
	script := capturedArgs[1]
	if !strings.Contains(script, "on run argv") {
		t.Errorf("script does not contain %q; got:\n%s", "on run argv", script)
	}

	// Verify title and message are passed as separate argv, not interpolated
	title := capturedArgs[2]
	message := capturedArgs[3]

	if title != "Test Title" {
		t.Errorf("expected title %q, got %q", "Test Title", title)
	}
	if message != "Test Message" {
		t.Errorf("expected message %q, got %q", "Test Message", message)
	}

	// Verify title/message are NOT in the script (no interpolation)
	if strings.Contains(script, "Test Title") {
		t.Errorf("title was interpolated into the script; should be passed as argv")
	}
	if strings.Contains(script, "Test Message") {
		t.Errorf("message was interpolated into the script; should be passed as argv")
	}
}

func TestSend_ContextCancelled(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	orig := commandBuilder
	defer func() { commandBuilder = orig }()

	commandBuilder = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Return a real command so context cancellation can take effect
		return exec.CommandContext(ctx, "osascript", args...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := Send(ctx, "Title", "Message")
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}
