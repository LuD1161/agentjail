//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

// logs_sigwinch_other.go — stub for platforms without SIGWINCH.
package main

import "os"

// registerSIGWINCH is a no-op on platforms that do not have SIGWINCH.
func registerSIGWINCH(_ chan<- os.Signal) {}
