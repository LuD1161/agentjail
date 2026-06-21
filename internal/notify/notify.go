package notify

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// commandBuilder creates exec.Cmd instances. Tests replace this to capture
// args without invoking real binaries.
var commandBuilder = exec.CommandContext

// Send dispatches an OS-native notification. On macOS it uses osascript with
// the "on run argv" pattern to avoid AppleScript string interpolation. On
// Linux it tries notify-send (best-effort).
func Send(ctx context.Context, title, message string) error {
	switch runtime.GOOS {
	case "darwin":
		return sendDarwin(ctx, title, message)
	case "linux":
		return sendLinux(ctx, title, message)
	default:
		return fmt.Errorf("notify: unsupported OS %q", runtime.GOOS)
	}
}

func sendDarwin(ctx context.Context, title, message string) error {
	script := `on run argv
	display notification (item 2 of argv) with title (item 1 of argv)
end run`
	cmd := commandBuilder(ctx, "osascript", "-e", script, title, message)
	return cmd.Run()
}

func sendLinux(ctx context.Context, title, message string) error {
	if _, err := exec.LookPath("notify-send"); err != nil {
		return fmt.Errorf("notify-send not found: %w", err)
	}
	cmd := commandBuilder(ctx, "notify-send", title, message)
	return cmd.Run()
}
