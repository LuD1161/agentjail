//go:build darwin

package shieldapp

import (
	"log/slog"
	"os/exec"
	"syscall"
)

// startAndWaitChild starts cmd, waits for it to complete, and returns the
// exit code this process should propagate via os.Exit. Mirrors shell exit
// convention: an ordinary exit returns its own code; a signal death returns
// 128+signal. exec.ExitError.ExitCode() alone returns -1 for a signaled
// child, and os.Exit(-1) silently becomes 255 -- losing the signal number
// and regressing Ctrl-C/SIGTERM parity versus the syscall.Exec path this
// replaces. Shared by every darwin spawn-and-wait site (tunnel and non-
// tunnel) so exit/signal handling can never drift between them. See A2,
// AGE-149 T1.7.
func startAndWaitChild(cmd *exec.Cmd, logger *slog.Logger) int {
	if err := cmd.Start(); err != nil {
		logger.Error("spawning agent failed", "err", err)
		return 1
	}
	err := cmd.Wait()
	if err == nil {
		return 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		logger.Error("waiting for agent failed", "err", err)
		return 1
	}
	if ws, wsOK := exitErr.Sys().(syscall.WaitStatus); wsOK && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return exitErr.ExitCode()
}
