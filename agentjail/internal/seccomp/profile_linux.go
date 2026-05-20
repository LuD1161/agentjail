//go:build linux

package seccomp

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sockFilter mirrors `struct sock_filter` from <linux/filter.h>.
// We re-declare the layout here (instead of unix.SockFilter) so the
// types are byte-identical to the kernel ABI and we control alignment.
type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// sockFprog mirrors `struct sock_fprog`.
type sockFprog struct {
	Len    uint16
	_      [6]byte // padding so Filter is 8-byte aligned on x86_64 + aarch64
	Filter *sockFilter
}

// Apply installs the filter on the calling thread. On success the
// filter inherits across exec() and fork() automatically (that is the
// whole point of seccomp-bpf — see seccomp(2) "INHERITANCE").
//
// IMPORTANT: this MUST be called BEFORE the Go runtime spawns extra
// threads that you don't want filtered (it doesn't matter for agentjail —
// every thread in the guest agent is filtered — but documenting the
// constraint anyway). Calling Apply from package main's init() is the
// recommended pattern.
//
// Apply also installs PR_SET_NO_NEW_PRIVS, which seccomp filter mode
// requires unless the caller has CAP_SYS_ADMIN. We always set it; in
// the agentjail guest we never want a child to acquire privileges via
// setuid binaries anyway (fail-closed; see docs/ENGINEERING.md §3).
func (p Profile) Apply() error {
	// Step 1: lock OS thread. seccomp is per-thread; if the Go runtime
	// migrates us mid-Apply the second prctl could land on the wrong
	// kernel task.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Step 2: build the BPF program.
	prog, err := p.compile()
	if err != nil {
		return err
	}

	// Step 3: PR_SET_NO_NEW_PRIVS=1 (required for seccomp filter mode
	// without CAP_SYS_ADMIN; man seccomp(2)). Idempotent — once set it
	// cannot be cleared, so re-calling Apply is safe.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL,
		unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("seccomp: PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	// Step 4: PR_SET_SECCOMP with mode=FILTER and the BPF program.
	fprog := sockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL,
		unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&fprog)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("seccomp: PR_SET_SECCOMP filter: %w", errno)
	}
	return nil
}

// compile turns the typed allowlist into a sock_filter program of the
// shape:
//
//	A = arch                  (seccomp_data.arch, offset 4, u32)
//	if A != AUDIT_ARCH_*  -> KILL_PROCESS    (defends against compat-arch evasion)
//	A = nr                    (seccomp_data.nr, offset 0, u32)
//	if A == nr1 -> ALLOW
//	if A == nr2 -> ALLOW
//	…
//	-> DefaultAction (KILL_PROCESS by default)
//
// Order of allowlist matters only for performance: the hottest syscalls
// (read/write/futex/epoll_pwait) sit near the top of Baseline so the
// average match is cheap.
//
// The arch guard is critical: without it a 32-bit syscall on x86_64
// (entered via int 0x80 or the i386 compat ABI) hits the filter with a
// different syscall numbering scheme — what is read(2)=0 on x86_64 is
// restart_syscall(2)=0 on i386. Always pin to the native arch.
func (p Profile) compile() ([]sockFilter, error) {
	auditArch, table, err := nativeArch()
	if err != nil {
		return nil, err
	}

	// Pre-resolve every allowlist name once.
	//
	// Three cases:
	//
	//   1. Name resolves on this arch -> add the nr to the filter.
	//   2. Name is in KnownNames (a typo-free list across every arch
	//      we support) but absent from this arch's table -> the
	//      syscall genuinely does not exist on this kernel arch
	//      (e.g. "open" on aarch64; the asm-generic UAPI dropped it
	//      in favor of "openat"). Skip silently — not a fallback,
	//      the syscall is uncallable here by definition.
	//   3. Name is not in KnownNames -> typo or never-existed name;
	//      error out (fail-closed, see docs/ENGINEERING.md §3).
	nrs := make([]uint32, 0, len(p.Allowlist))
	seen := make(map[uint32]struct{}, len(p.Allowlist))
	for _, name := range p.Allowlist {
		nr, ok := table[name]
		if !ok {
			if _, known := KnownNames[name]; known {
				continue // case 2
			}
			return nil, fmt.Errorf("%w: %q (arch=%s)", ErrUnknownSyscall, name, runtime.GOARCH)
		}
		if _, dup := seen[nr]; dup {
			continue
		}
		seen[nr] = struct{}{}
		nrs = append(nrs, nr)
	}

	defaultRet := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	if p.DefaultAction == ActionErrno {
		defaultRet = uint32(unix.SECCOMP_RET_ERRNO) | (1 & uint32(unix.SECCOMP_RET_DATA)) // EPERM
	}

	allow := uint32(unix.SECCOMP_RET_ALLOW)

	const (
		// Offsets into struct seccomp_data { nr, arch, ip, args[6] }.
		offsetNr   = 0
		offsetArch = 4
	)

	prog := make([]sockFilter, 0, 4+len(nrs)+1)

	// Load arch, compare to native.
	prog = append(prog,
		sockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offsetArch},
		// if A == auditArch jump 1 (skip the kill); else fall through to kill.
		sockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 1, Jf: 0},
		sockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_KILL_PROCESS)},
	)

	// Load nr.
	prog = append(prog,
		sockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offsetNr},
	)

	// One JEQ per allowed syscall — on match, jump to the ALLOW return
	// at the tail of the program. We compute the relative offset at
	// emit time; remaining filters after this one count toward the
	// jump target.
	//
	// Layout for the tail: <N jeqs> <default-ret> <allow-ret>
	// So for jeq index i (0-based): jt = (len(nrs) - 1 - i) + 1
	// — skip the remaining JEQs and the default-ret, land on ALLOW.
	for i, nr := range nrs {
		jt := uint8(len(nrs) - 1 - i + 1) // +1 to skip the default-ret instruction
		prog = append(prog,
			sockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: nr, Jt: jt, Jf: 0},
		)
	}
	prog = append(prog,
		sockFilter{Code: unix.BPF_RET | unix.BPF_K, K: defaultRet},
		sockFilter{Code: unix.BPF_RET | unix.BPF_K, K: allow},
	)

	// BPF programs are capped at 4096 instructions (BPF_MAXINSNS).
	// Our allowlist is well under that, but assert to fail loud if
	// a future contributor blows past it.
	if len(prog) > 4096 {
		return nil, fmt.Errorf("seccomp: BPF program too large: %d insns (max 4096)", len(prog))
	}
	return prog, nil
}

// nativeArch returns the AUDIT_ARCH_* constant for the running GOARCH
// and the matching syscall-name -> nr table.
//
// The per-arch table (nativeSyscalls) and audit constant (nativeAudit)
// are defined in tables_linux_<arch>.go — one file per supported
// architecture. Adding a new arch (riscv64, etc.) is a one-file change.
func nativeArch() (uint32, map[string]uint32, error) {
	if nativeAudit == 0 {
		// nativeAudit is set by a per-arch tables file; zero means we
		// were compiled for an unsupported arch.
		return 0, nil, fmt.Errorf("%w: GOARCH=%s", ErrUnsupportedArch, runtime.GOARCH)
	}
	return nativeAudit, nativeSyscalls, nil
}
