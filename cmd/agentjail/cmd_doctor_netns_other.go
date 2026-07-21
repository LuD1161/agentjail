//go:build !linux

package main

import "fmt"

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

// repairApparmorUsernsApply is a no-op on non-Linux platforms: the scoped
// AppArmor userns profile (ADR 0104-shield-apparmor-userns) is Linux-only.
func repairApparmorUsernsApply(_ string) error {
	return fmt.Errorf("AppArmor userns profile is Linux-only")
}

func repairApparmorUsernsRecheck(_ string) doctorCheck {
	return doctorCheck{label: "Network interception", status: "skip", detail: "Linux-only"}
}
