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
func ApplyHardening() error {
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

	// 4. Make the process non-dumpable so a same-uid process cannot ptrace or
	//    read its memory during the pre-exec window. Note: DUMPABLE resets to 1
	//    on the next execve unless re-applied, so this is defense-in-depth for
	//    the window before we exec the untrusted agent, not a permanent state.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: PR_SET_DUMPABLE: %w", err)
	}

	return nil
}
