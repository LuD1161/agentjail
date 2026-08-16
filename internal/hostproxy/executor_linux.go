//go:build linux

package hostproxy

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

type platformExecutor struct{}

func (platformExecutor) Execute(ctx context.Context, target Target, cwd string, timeout time.Duration, outputLimit int, onStarted func(int)) Result {
	return executePlatform(ctx, target, cwd, timeout, outputLimit, onStarted)
}

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
