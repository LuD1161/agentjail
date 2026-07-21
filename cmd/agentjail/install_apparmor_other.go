//go:build !linux

package main

import (
	"fmt"
	"os"

	"github.com/LuD1161/agentjail/internal/ui"
)

// installWithApparmor is a no-op off Linux: the AppArmor userns profile is a
// Linux-only remedy for Ubuntu's kernel.apparmor_restrict_unprivileged_userns.
// See ADR 0104-shield-apparmor-userns.
func installWithApparmor(home string, assumeYes bool) error {
	fmt.Fprintln(os.Stdout, ui.New(os.Stdout).Badge("dim",
		"agentjail: --with-apparmor is not applicable on this OS (Linux only). Nothing changed."))
	return nil
}

// networkVisibilityStatusLine has nothing to report off Linux — the userns
// restriction it speaks to is a Linux/Ubuntu concern.
func networkVisibilityStatusLine() (string, bool) { return "", false }
