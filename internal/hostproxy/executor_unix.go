//go:build linux || darwin

package hostproxy

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

type combinedCapture struct {
	mu         sync.Mutex
	remaining  int
	overflowed bool
	overflow   chan struct{}
	once       sync.Once
	stdout     bytes.Buffer
	stderr     bytes.Buffer
}

type streamCapture struct {
	owner  *combinedCapture
	stderr bool
}

func (w streamCapture) Write(p []byte) (int, error) {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	if len(p) > w.owner.remaining {
		w.owner.overflowed = true
		if w.owner.remaining > 0 {
			if w.stderr {
				_, _ = w.owner.stderr.Write(p[:w.owner.remaining])
			} else {
				_, _ = w.owner.stdout.Write(p[:w.owner.remaining])
			}
			w.owner.remaining = 0
		}
		w.owner.once.Do(func() { close(w.owner.overflow) })
		return len(p), nil
	}
	w.owner.remaining -= len(p)
	if w.stderr {
		_, _ = w.owner.stderr.Write(p)
	} else {
		_, _ = w.owner.stdout.Write(p)
	}
	return len(p), nil
}

func executePlatform(ctx context.Context, target Target, cwd string, timeout time.Duration, outputLimit int, onStarted func(int)) Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if outputLimit <= 0 {
		outputLimit = DefaultOutputLimit
	}
	startTime := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	capture := &combinedCapture{remaining: outputLimit, overflow: make(chan struct{})}
	cmd := exec.Command(target.Executable, target.Argv[1:]...)
	cmd.Args[0] = target.Argv[0]
	cmd.Dir = cwd
	cmd.Stdout = streamCapture{owner: capture}
	cmd.Stderr = streamCapture{owner: capture, stderr: true}
	cmd.Stdin = nil
	configureProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return Result{ExitCode: -1, Reason: "spawn_failed", Duration: time.Since(startTime)}
	}
	if onStarted != nil {
		onStarted(cmd.Process.Pid)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	result := Result{ExitCode: 0}
	select {
	case err := <-waitCh:
		result.ExitCode = exitCode(err)
	case <-runCtx.Done():
		_ = killProcessGroup(cmd.Process.Pid)
		<-waitCh
		result.ExitCode = -1
		result.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
		if result.TimedOut {
			result.Reason = "timeout"
		} else {
			result.Reason = "cancelled"
		}
	case <-capture.overflow:
		_ = killProcessGroup(cmd.Process.Pid)
		<-waitCh
		result.ExitCode = -1
		result.Truncated = true
		result.Reason = "output_limit"
	}
	capture.mu.Lock()
	if capture.overflowed {
		result.ExitCode = -1
		result.Truncated = true
		result.Reason = "output_limit"
	}
	result.Stdout = append([]byte(nil), capture.stdout.Bytes()...)
	result.Stderr = append([]byte(nil), capture.stderr.Bytes()...)
	capture.mu.Unlock()
	result.Duration = time.Since(startTime)
	return result
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
