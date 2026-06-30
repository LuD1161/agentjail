//go:build darwin

package main

// checkNoNewPrivs is a no-op on macOS. Landlock (and thus NoNewPrivs) is
// Linux-only; the HTTPS_PROXY heuristic in checkShieldStatus covers macOS.
func checkNoNewPrivs() bool {
	return false
}
