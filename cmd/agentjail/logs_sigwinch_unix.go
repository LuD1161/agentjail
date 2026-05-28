//go:build darwin || linux || freebsd || openbsd || netbsd

// logs_sigwinch_unix.go — registers SIGWINCH for window-resize events on Unix.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

// registerSIGWINCH starts forwarding SIGWINCH events to ch.
// Called from runLogs before the stream loop begins.
func registerSIGWINCH(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGWINCH)
}
