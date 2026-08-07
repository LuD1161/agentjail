//go:build linux || darwin

package shieldapp

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/LuD1161/agentjail/internal/localui"
)

func startDetachedLocalUI() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve agentjail executable: %w", err)
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
	}
	defer devnull.Close()

	cmd := exec.Command(exe, "ui", "--addr", localui.DefaultAddr)
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start UI process: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release UI process: %w", err)
	}
	return nil
}
