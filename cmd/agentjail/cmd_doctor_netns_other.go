//go:build !linux

package main

// checkNetworkInterception is a no-op on non-Linux platforms: the transparent
// tunnel path (AGE-148) is Linux-only. macOS intercepts traffic via a Network
// Extension instead, so there is nothing to probe here.
func checkNetworkInterception() []doctorCheck {
	return []doctorCheck{
		{
			label:  "Network interception",
			status: "skip",
			detail: "Linux-only (macOS uses a Network Extension)",
		},
	}
}
