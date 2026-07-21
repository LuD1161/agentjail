//go:build linux

package netns

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Securebits flags. These are defined by <linux/securebits.h> but are NOT
// exported by golang.org/x/sys/unix (v0.45.0), so we declare them locally with
// their canonical numeric values. Each SECBIT_* is issecure_mask(SECURE_*),
// i.e. (1 << SECURE_*):
//
//	SECURE_NOROOT                = 0 -> SECBIT_NOROOT                = 1<<0
//	SECURE_NOROOT_LOCKED         = 1 -> SECBIT_NOROOT_LOCKED         = 1<<1
//	SECURE_NO_SETUID_FIXUP       = 2 -> SECBIT_NO_SETUID_FIXUP       = 1<<2
//	SECURE_NO_SETUID_FIXUP_LOCKED= 3 -> SECBIT_NO_SETUID_FIXUP_LOCKED= 1<<3
//	SECURE_KEEP_CAPS             = 4 -> SECBIT_KEEP_CAPS             = 1<<4
//	SECURE_KEEP_CAPS_LOCKED      = 5 -> SECBIT_KEEP_CAPS_LOCKED      = 1<<5
const (
	secbitNoRoot              = 1 << 0 // SECBIT_NOROOT
	secbitNoRootLocked        = 1 << 1 // SECBIT_NOROOT_LOCKED
	secbitNoSetuidFixup       = 1 << 2 // SECBIT_NO_SETUID_FIXUP
	secbitNoSetuidFixupLocked = 1 << 3 // SECBIT_NO_SETUID_FIXUP_LOCKED
	secbitKeepCapsLocked      = 1 << 5 // SECBIT_KEEP_CAPS_LOCKED

	// hardenSecurebits is the securebits value applied by ApplyHardening.
	// SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
	// SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED = 0x2f (47).
	hardenSecurebits = secbitNoRoot |
		secbitNoRootLocked |
		secbitNoSetuidFixup |
		secbitNoSetuidFixupLocked |
		secbitKeepCapsLocked
)

// ApplyHardening locks down the CURRENT process against privilege escalation
// before it execs an untrusted agent inside an unprivileged user namespace
// (where the caller is mapped to uid 0). It is the ClawPatrol cap-drop/secbits
// lifecycle: after this returns, the process (and everything it execs) cannot
// regain privileges via setuid binaries, ambient capabilities, or ptrace.
//
// The two halves are separable for the nested-userns tunnel path (AGE-261):
// ApplyCapHardening MUST run while the process still holds caps (securebits need
// CAP_SETPCAP), and ApplyDumpableGuard MUST run in the process that will execve
// the agent (DUMPABLE resets on execve). On the non-nested path both run here in
// one process, preserving the original behavior.
func ApplyHardening() error {
	if err := ApplyCapHardening(); err != nil {
		return err
	}
	return ApplyDumpableGuard()
}

// ApplyCapHardening applies the steps that require capabilities and/or must
// precede a privilege-dropping execve: no_new_privs, ambient-clear, and the
// securebits lockdown. All three preserve across clone(2) and execve(2), so for
// the nested-userns tunnel path this runs in the shim (still uid 0 with caps in
// the holder userns) and is inherited by the non-root agent. See AGE-261.
func ApplyCapHardening() error {
	// 1. No new privileges: setuid/setgid bits and file capabilities are
	//    ignored across execve, and this is a precondition for the securebits
	//    lockdown below. Once set it cannot be unset.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// 2. Drop all ambient capabilities so none are inherited across execve.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_CAP_AMBIENT_CLEAR_ALL: %w", err)
	}

	// 3. Lock securebits: uid 0 no longer implies special treatment
	//    (NOROOT), setuid transitions no longer adjust the capability sets
	//    (NO_SETUID_FIXUP), and each is *_LOCKED so it cannot be undone. The
	//    KEEP_CAPS flag is locked off so capabilities are still dropped on a
	//    setuid(nonzero) transition.
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(hardenSecurebits), 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_SET_SECUREBITS(0x%x): %w", hardenSecurebits, err)
	}
	return nil
}

// ApplyUnprivilegedHardening applies the hardening steps that need NO
// capabilities and so work for a non-root process: no_new_privs, ambient-cap
// clear, and the dumpable guard. It omits the securebits lockdown on purpose
// (PR_SET_SECUREBITS needs CAP_SETPCAP). In the nested-userns tunnel path
// (AGE-261) the agent is genuinely non-root, and creating the nested userns
// RESETS securebits and the bounding set anyway (verified: the nested agent
// reports Securebits 0x0), so securebits cannot be delivered there. no_new_privs
// -- which IS irreversible and survives the nested clone+execve -- is what
// carries the escalation-prevention: with it set and an empty permitted set, the
// full bounding set is unreachable (no file-cap execve can add to permitted).
func ApplyUnprivilegedHardening() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_CAP_AMBIENT_CLEAR_ALL: %w", err)
	}
	return ApplyDumpableGuard()
}

// ApplyDumpableGuard makes the process non-dumpable so a same-uid process cannot
// ptrace or read its memory during the pre-exec window. DUMPABLE resets to 1 on
// the next execve unless re-applied, so this is defense-in-depth for the window
// before exec of the untrusted agent, and must run in the process that execs it
// (not an earlier ancestor). Needs no capabilities.
func ApplyDumpableGuard() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_SET_DUMPABLE: %w", err)
	}
	return nil
}
