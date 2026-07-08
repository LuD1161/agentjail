//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// checkNetworkInterception probes the two kernel capabilities the transparent
// tunnel path (AGE-148) depends on: unprivileged user namespaces and
// /dev/net/tun. When both are available the shield can run the transparent
// forwarder; when either is missing the shield falls back to netproxy, which is
// a supported, documented configuration (ADR 0049). These checks are therefore
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

	detail := "disabled — transparent tunnel unavailable, shield falls back to netproxy; check sysctls kernel.unprivileged_userns_clone, user.max_user_namespaces and AppArmor kernel.apparmor_restrict_unprivileged_userns"
	if hint := unprivilegedUsernsSysctlHint(); hint != "" {
		detail += " (" + hint + ")"
	}
	return doctorCheck{
		label:  "Unprivileged user namespaces",
		status: "fail",
		detail: detail,
	}
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
