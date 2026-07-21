//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/term"

	"github.com/LuD1161/agentjail/internal/apparmor"
	"github.com/LuD1161/agentjail/internal/ui"
)

// installWithApparmor runs the consent-gated `agentjail install --with-apparmor`
// flow: load the scoped userns profile so the transparent tunnel works on a host
// with kernel.apparmor_restrict_unprivileged_userns=1, with no system-wide
// weakening. The single privileged step (needs root once), consent-gated.
// See ADR 0104-shield-apparmor-userns.
func installWithApparmor(home string, assumeYes bool) error {
	u := ui.New(os.Stdout)

	// Under sudo the profile must attach to — and the consent marker land in —
	// the INVOKING user's home, not root's: doctor runs as the user and reads
	// ~/.agentjail/apparmor-consent, and the profile guards ~/.agentjail/bin.
	targetHome := apparmorTargetHome(home)
	installDir := filepath.Join(targetHome, ".agentjail", "bin")

	avail, err := apparmor.New().Available()
	if err != nil {
		return err
	}
	if !avail.Supported {
		fmt.Fprintln(os.Stdout, u.Badge("dim",
			"agentjail: transparent tunnel unavailable on this host — AppArmor 4.x required ("+
				apparmorAvailSummary(avail)+"). Nothing changed."))
		return nil
	}

	profile := apparmor.New().Render(installDir)
	printApparmorConsent(u, installDir, profile)

	if !apparmorProceed(assumeYes) {
		fmt.Fprintln(os.Stdout, u.Badge("dim",
			"agentjail: declined — network capture stays OFF. Core protection (commands, files, MCP, sandbox) is unaffected."))
		return nil
	}

	if err := apparmor.New().Install(installDir); err != nil {
		if errors.Is(err, apparmor.ErrNotRoot) {
			return errors.New("loading the AppArmor profile needs root — re-run: sudo agentjail install --with-apparmor")
		}
		return err
	}

	if err := writeApparmorConsent(targetHome); err != nil {
		return fmt.Errorf("profile loaded but recording consent failed: %w", err)
	}

	fmt.Fprintln(os.Stdout, u.Badge("ok",
		"agentjail: scoped AppArmor profile loaded — network visibility is ON. Nothing else on your system changed."))
	return nil
}

// apparmorProceed decides whether to load the profile without asking: assume-yes
// (flag/env) or a non-interactive stdin (testbed automation) proceed silently;
// an interactive stdin requires a typed 'y'. See ADR 0104-shield-apparmor-userns.
func apparmorProceed(assumeYes bool) bool {
	if assumeYes || !term.IsTerminal(int(os.Stdin.Fd())) {
		return true
	}
	return requireInteractiveConfirm(
		"agentjail: no terminal to confirm on — re-run with --yes to proceed non-interactively.\n",
		"Proceed? [y/N] ")
}

// printApparmorConsent shows the exact privileged commands and the profile text
// that will be written, before anything runs.
func printApparmorConsent(u *ui.UI, installDir, profile string) {
	fmt.Fprintln(os.Stdout, u.Badge("info",
		"agentjail wants to enable network visibility for its OWN binary only, via a scoped AppArmor profile."))
	fmt.Fprintln(os.Stdout, "  This needs root once. It runs, as root:")
	fmt.Fprintln(os.Stdout, "    sudo tee /etc/apparmor.d/agentjail-shield   # writes the profile below")
	fmt.Fprintln(os.Stdout, "    sudo apparmor_parser -r /etc/apparmor.d/agentjail-shield")
	fmt.Fprintln(os.Stdout, "  It weakens nothing else on your machine (ADR 0104-shield-apparmor-userns).")
	fmt.Fprintln(os.Stdout, "  Profile (attaches to "+installDir+"/agentjail{,-shield}):")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, indentBlock(profile, "    "))
}

// indentBlock prefixes every line of s with prefix.
func indentBlock(s, prefix string) string {
	out := ""
	for i, line := range splitLines(s) {
		if i > 0 {
			out += "\n"
		}
		out += prefix + line
	}
	return out
}

// splitLines splits on '\n' without a trailing empty element for a terminal newline.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// writeApparmorConsent records the opt-in doctor reads to unblock `doctor --fix`.
// 0600, and chown'd to the invoking user under sudo so they can manage it.
// See ADR 0104-shield-apparmor-userns.
func writeApparmorConsent(home string) error {
	marker := apparmorConsentMarker(home)
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(marker, []byte("1\n"), 0o600); err != nil {
		return err
	}
	if uid, gid, ok := sudoInvokerIDs(); ok {
		_ = os.Chown(marker, uid, gid)
	}
	return nil
}

// apparmorAvailSummary is a short human description of why a host is unsupported.
func apparmorAvailSummary(a apparmor.Availability) string {
	if !a.ParserFound {
		return "no apparmor_parser"
	}
	return "apparmor_parser " + a.ParserVersion.String()
}

// apparmorTargetHome returns the invoking user's home when run under sudo, else
// the passed-in home. See ADR 0104-shield-apparmor-userns.
func apparmorTargetHome(home string) string {
	if os.Geteuid() != 0 {
		return home
	}
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	return home
}

// sudoInvokerIDs returns the SUDO_UID/SUDO_GID of the invoking user, if present.
func sudoInvokerIDs() (uid, gid int, ok bool) {
	us, gs := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if us == "" || gs == "" {
		return 0, 0, false
	}
	uid, uerr := strconv.Atoi(us)
	gid, gerr := strconv.Atoi(gs)
	if uerr != nil || gerr != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// networkVisibilityStatusLine is the summary line reported after `agentjail
// install`. It is shown only when it has something to say: the profile is
// active (consent recorded) → ON; or Ubuntu's userns restriction is on but the
// profile isn't loaded → OFF hint. On unrestricted hosts (Debian/Fedora, where
// the tunnel already works) it stays silent. See ADR 0104-shield-apparmor-userns.
func networkVisibilityStatusLine() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	return networkVisibilityLine(apparmorUsernsRestricted(), apparmorConsentRecorded(home))
}

// networkVisibilityLine is the pure ON/OFF selection, split out so the
// restriction-on vs -off cases are unit-testable without touching /proc or root.
func networkVisibilityLine(restricted, consented bool) (string, bool) {
	switch {
	case consented:
		return "✅  Network visibility: ON (scoped AppArmor profile — nothing else on your system changed)", true
	case restricted:
		return "○  Network visibility: OFF — run 'agentjail install --with-apparmor' (one-time sudo). Core protection is active.", true
	default:
		return "", false
	}
}
