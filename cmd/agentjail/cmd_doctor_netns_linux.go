//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/LuD1161/agentjail/internal/apparmor"
)

// checkNetworkInterception probes the two kernel capabilities the transparent
// tunnel path (AGE-148) depends on: unprivileged user namespaces and
// /dev/net/tun. When both are available the shield can run the transparent
// forwarder; when either is missing the shield falls back to netproxy, which is
// a supported, documented configuration (ADR 0079). These checks are therefore
// informational — runDoctor must not fold them into hasFailure.
func checkNetworkInterception() []doctorCheck {
	var checks []doctorCheck

	checks = append(checks, checkUnprivilegedUserns())
	checks = append(checks, checkDevNetTun())

	return checks
}

// checkUnprivilegedUserns is the source of truth for whether this host allows
// unprivileged user namespaces: it actually attempts to spawn a child in a new
// user namespace. Reading the sysctl files alone is unreliable across distros
// (AppArmor, seccomp, and container runtimes can all block it independently), so
// the live spawn result decides ok/fail; the sysctls only enrich the detail.
func checkUnprivilegedUserns() doctorCheck {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}

	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	if err == nil {
		return doctorCheck{
			label:  "Unprivileged user namespaces",
			status: "ok",
			detail: "enabled",
		}
	}

	// The AppArmor restriction is the one block agentjail can lift for its own
	// binary — the scoped profile — with no system-wide weakening. That single
	// remediation is the whole story; there is no netproxy fallback to mention.
	// See ADR 0104-shield-apparmor-userns.
	if fix := usernsRemediation(); fix != "" {
		return doctorCheck{
			label:  "Network interception",
			status: "fail",
			repair: repairApparmorUserns,
			detail: "OFF — " + fix,
		}
	}

	detail := "disabled — transparent tunnel unavailable; check sysctls " +
		"kernel.unprivileged_userns_clone, user.max_user_namespaces and AppArmor " +
		"kernel.apparmor_restrict_unprivileged_userns"
	if hint := unprivilegedUsernsSysctlHint(); hint != "" {
		detail += " (" + hint + ")"
	}
	return doctorCheck{
		label:  "Unprivileged user namespaces",
		status: "fail",
		detail: detail,
	}
}

// usernsRemediation returns the single ADR 0104 remediation when the userns
// block is Ubuntu 23.10+'s AppArmor restriction: install the scoped per-binary
// profile. Empty otherwise. NO global sysctl flip — weakening userns for every
// binary on the machine to enable one is the wrong trade for a security tool.
// See ADR 0104-shield-apparmor-userns.
func usernsRemediation() string {
	if !apparmorUsernsRestricted() {
		return ""
	}
	return "The transparent tunnel needs an unprivileged user namespace, which\n" +
		"  this host restricts (kernel.apparmor_restrict_unprivileged_userns=1).\n" +
		"  agentjail enables it for its OWN binary only — it will not weaken this\n" +
		"  setting for anything else on your machine.\n\n" +
		"  Turn it on (one-time sudo):  agentjail install --with-apparmor\n\n" +
		"  Core protection — commands, files, MCP, sandbox — is active and needs\n" +
		"  no sudo. This only adds network visibility."
}

// apparmorUsernsRestricted reports whether Ubuntu's AppArmor userns restriction
// is the active block (kernel.apparmor_restrict_unprivileged_userns=1).
func apparmorUsernsRestricted() bool {
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// repairApparmorUsernsApply installs the scoped AppArmor userns profile. Gated
// on recorded consent — a repair the user never consented to must not run, and
// this one needs root once. Mirrors restorePathShim's consent gate.
// See ADR 0104-shield-apparmor-userns.
func repairApparmorUsernsApply(home string) error {
	if !apparmorConsentRecorded(home) {
		return fmt.Errorf("no recorded opt-in for the AppArmor userns profile — run `agentjail install --with-apparmor`")
	}
	installDir := filepath.Join(home, ".agentjail", "bin")
	return apparmor.New().Install(installDir)
}

// repairApparmorUsernsRecheck re-runs the live CLONE_NEWUSER probe, so the
// reported state is observed, not the repair's return value (ADR 0086).
func repairApparmorUsernsRecheck(home string) doctorCheck {
	return checkUnprivilegedUserns()
}

// apparmorConsentMarker is the recorded opt-in for loading the scoped AppArmor
// profile, written by `agentjail install --with-apparmor`. Its presence is the
// only thing that lets `doctor --fix` load the profile (needs root once).
func apparmorConsentMarker(home string) string {
	return filepath.Join(home, ".agentjail", "apparmor-consent")
}

// apparmorConsentRecorded reports whether the user opted into the AppArmor
// profile. See ADR 0104-shield-apparmor-userns.
func apparmorConsentRecorded(home string) bool {
	_, err := os.Stat(apparmorConsentMarker(home))
	return err == nil
}

// unprivilegedUsernsSysctlHint reads the relevant sysctls best-effort to enrich
// the failure detail. It never decides ok/fail — that is the spawn probe's job.
func unprivilegedUsernsSysctlHint() string {
	var parts []string
	for _, s := range []struct {
		path string
		name string
	}{
		{"/proc/sys/kernel/unprivileged_userns_clone", "kernel.unprivileged_userns_clone"},
		{"/proc/sys/user/max_user_namespaces", "user.max_user_namespaces"},
		{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "kernel.apparmor_restrict_unprivileged_userns"},
	} {
		if b, err := os.ReadFile(s.path); err == nil {
			parts = append(parts, fmt.Sprintf("%s=%s", s.name, strings.TrimSpace(string(b))))
		}
	}
	return strings.Join(parts, ", ")
}

// checkDevNetTun probes /dev/net/tun, the character device the transparent
// forwarder opens to receive packets. A missing device means the tun module is
// not loaded; an EPERM means the device exists but this process cannot open it.
func checkDevNetTun() doctorCheck {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return doctorCheck{
			label:  "/dev/net/tun",
			status: "ok",
			detail: "openable",
		}
	}
	if os.IsNotExist(err) {
		return doctorCheck{
			label:  "/dev/net/tun",
			status: "fail",
			detail: "not present (tun module not loaded / device missing) — shield falls back to netproxy",
		}
	}
	if os.IsPermission(err) {
		return doctorCheck{
			label:  "/dev/net/tun",
			status: "warn",
			detail: "present but not openable (EPERM) — shield falls back to netproxy",
		}
	}
	return doctorCheck{
		label:  "/dev/net/tun",
		status: "warn",
		detail: fmt.Sprintf("cannot open: %v — shield falls back to netproxy", err),
	}
}
