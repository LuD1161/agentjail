// Package seccomp builds and applies a default-deny syscall filter for the
// guest agent process inside agentjail's Linux microVM substrate.
//
// Design (KISS — see docs/ENGINEERING.md §1):
//
//   - The allowlist is a typed []string of syscall names, baseline-seeded
//     from a real Claude/Codex/Aider strace and reviewed entry-by-entry.
//   - Any syscall not on the list is denied with KILL_PROCESS by default
//     (no SIGSYS-rescue, no learning mode) — agentjail is fail-closed
//     enforcement, not telemetry.
//   - On Linux we install the filter ourselves via two prctl(2) calls,
//     building the seccomp-BPF program by hand. We deliberately do NOT
//     pull in seccomp/libseccomp-golang (a cgo wrapper over libseccomp.so):
//     adding a C library dependency for ~40 lines of byte-code violates
//     KISS and breaks pure-Go static linking. See
//     agentjail/docs/DECISIONS.md (seccomp design entry).
//   - On macOS the package compiles but Apply() returns ErrUnsupported,
//     so the agentjail-host tooling can import this package on the
//     developer workstation without losing platform parity.
//
// Architecture matrix: x86_64 (AUDIT_ARCH_X86_64) and aarch64
// (AUDIT_ARCH_AARCH64) only. The microVM substrate targets those two —
// see docs/MAP.md / agentjail/research/libkrun-spike. Booting under a
// third arch fails closed with ErrUnsupportedArch.
package seccomp

import "errors"

// Action is the outcome for a syscall that does not match the allowlist.
type Action uint32

const (
	// ActionKillProcess kills the whole process (SECCOMP_RET_KILL_PROCESS).
	// This is the default and the only action used in production:
	// fail-closed enforcement matches docs/ENGINEERING.md §3 ("no silent
	// fallbacks"). A learning-mode log-only action is intentionally NOT
	// exposed — telemetry of denied syscalls belongs to eBPF / audit
	// surfaces (eBPF/audit layer), not the enforcement filter.
	ActionKillProcess Action = iota
	// ActionErrno returns -EPERM (1) from the syscall. Exposed for tests
	// only — production callers must not use this.
	ActionErrno
)

// Profile is the typed configuration for one application of the seccomp
// filter. Build it with Default(), tweak via With…(), then call Apply()
// from a Linux runtime.
//
// Profile is immutable after construction (each With… returns a new
// value). That gives us trivially-correct concurrent reuse without a
// mutex.
type Profile struct {
	// Allowlist is the set of syscall *names* that are permitted. Names
	// are matched case-sensitively against the kernel's UAPI table
	// (asm-generic/unistd.h + per-arch overrides). Unknown names cause
	// Apply() to return an error rather than silently dropping them —
	// see docs/ENGINEERING.md §3 ("no silent fallbacks").
	Allowlist []string
	// DefaultAction is the action taken for any syscall NOT on the
	// Allowlist. Production deployments must use ActionKillProcess.
	DefaultAction Action
}

// ErrUnsupported is returned from Apply on non-Linux platforms.
var ErrUnsupported = errors.New("seccomp: only supported on linux")

// ErrUnsupportedArch is returned when Apply is invoked on a Linux kernel
// running on an architecture other than x86_64 or aarch64.
var ErrUnsupportedArch = errors.New("seccomp: unsupported architecture; want x86_64 or aarch64")

// ErrUnknownSyscall is returned when the Allowlist contains a name the
// package's syscall table does not know about for the current
// architecture. We never silently drop unknown names — a typo in the
// allowlist would be a security-critical bug.
var ErrUnknownSyscall = errors.New("seccomp: unknown syscall in allowlist")

// Baseline is the allowlist Claude/Codex/Aider actually need to run an
// interactive agent loop inside an agentjail guest. Every entry is
// annotated with the smallest justification ("WHY") and a citation to
// the strace surface where we observed it ("OBS").
//
// OBS labels:
//
//	C   = observed in a Claude Code session strace (CLI + tool loop)
//	C+  = Claude tool execution (file edits, bash via the Bash tool)
//	X   = Codex CLI / Aider — same shape, slight differences noted
//	G   = Go runtime fundamentals (the agent host is a Go binary)
//	L   = libc / dynamic loader bring-up (glibc, musl-ldd)
//
// When you add an entry, append it to the END of this slice with the
// same comment shape, and document WHY in agentjail/docs/DECISIONS.md.
// When you remove one, prove from a fresh strace that nothing needs it.
var Baseline = []string{
	// --- File I/O (every agent reads/writes the workspace) ---
	"read",       // WHY: every fd read.                              OBS: C, C+, X
	"write",      // WHY: every fd write incl. stdout, sockets.       OBS: C, C+, X
	"open",       // WHY: glibc still uses open(2) on x86_64 for      OBS: L
	              //      AT_FDCWD-relative paths in older libc.
	"openat",     // WHY: modern open path used by Go + musl + new glibc. OBS: C, G
	"openat2",    // WHY: io_uring / new glibc fopen.                 OBS: C (kernel >=5.6)
	"close",      // WHY: paired with every open.                     OBS: C
	"lseek",      // WHY: editors seek; Claude's str-replace tool does. OBS: C+
	"pread64",    // WHY: Go's os.ReadAt + dynamic-loader page reads. OBS: G, L
	"pwrite64",   // WHY: Go's os.WriteAt.                            OBS: G
	"readv",      // WHY: net/http body decoding.                     OBS: G
	"writev",     // WHY: Go's bufio + net.Conn vectored writes.      OBS: G
	"stat",       // WHY: os.Stat on x86_64 glibc (legacy path).      OBS: L
	"fstat",      // WHY: every fstat-after-open. Required by Go ELF.  OBS: G
	"lstat",      // WHY: filepath.Walk; symlink-not-followed lookups. OBS: C+
	"newfstatat", // WHY: modern AT_FDCWD stat path (Go, musl).       OBS: G
	"statx",      // WHY: glibc >=2.33 + Go 1.22 statx fast path.     OBS: G
	"access",     // WHY: dynamic-loader DT_RPATH probes.             OBS: L
	"faccessat2", // WHY: modern access() replacement.                OBS: L (kernel >=5.8)
	"readlink",   // WHY: glibc resolves /proc/self/exe; Go runtime   OBS: L, G
	              //      uses it to discover argv[0].
	"readlinkat", // WHY: modern variant.                             OBS: G
	"getcwd",     // WHY: agents print pwd; Go's os.Getwd.            OBS: C
	"getdents64", // WHY: filepath.Walk + ls.                         OBS: C+
	"fcntl",      // WHY: SETFD CLOEXEC, F_GETFL, F_SETFL non-block.  OBS: G
	"dup",        // WHY: redirection in subprocess bring-up.         OBS: C+
	"dup2",       // WHY: pre-dup3 stdio remap.                       OBS: C+ (glibc)
	"dup3",       // WHY: modern dup with O_CLOEXEC.                  OBS: G
	"pipe2",      // WHY: subprocess stdout/stderr capture.           OBS: C+
	"umask",      // WHY: subprocess bring-up sets umask.             OBS: C+
	"fstatfs",    // WHY: Go's syscall.Statfs for tmp dir checks.     OBS: G
	"chdir",      // WHY: cd inside the bash tool's sandboxed shell.  OBS: C+
	"fchdir",     // WHY: Go's os.Chdir relative form.                OBS: G

	// --- Memory ---
	"mmap",         // WHY: every Go heap arena reservation, libc text. OBS: G, L
	"munmap",       // WHY: arena unmaps.                               OBS: G
	"mprotect",     // WHY: Go GC + ld.so relocations (RW->RX flip).    OBS: G, L
	"brk",          // WHY: glibc malloc; Go runtime never calls it     OBS: L
	                //      but ld.so does during bring-up.
	"madvise",      // WHY: Go GC issues MADV_DONTNEED / MADV_FREE.     OBS: G
	"memfd_create", // WHY: Go's exec + some loggers use sealed memfds. OBS: G

	// --- Signals ---
	"rt_sigaction",      // WHY: Go runtime registers SIGURG, SIGPIPE…  OBS: G
	"rt_sigprocmask",    // WHY: per-thread signal mask on M switching. OBS: G
	"rt_sigreturn",      // WHY: required to return from signal handlers; OBS: G
	                     //      without it, any signal kills the process.
	"sigaltstack",       // WHY: Go runtime installs an alt-stack per M. OBS: G
	"kill",              // WHY: Go runtime kills child workers on panic. OBS: G
	"tkill",             // WHY: Go runtime thread-targeted kill.        OBS: G
	"tgkill",            // WHY: pthread_cancel + Go preemption signals. OBS: G
	"pidfd_send_signal", // WHY: pidfd-based child kill (Go >=1.20).     OBS: G

	// --- Process lifecycle ---
	"clone",           // WHY: pthread_create + Go M creation.         OBS: G
	"clone3",          // WHY: modern fork/thread on glibc >=2.34.     OBS: G, L
	"fork",            // WHY: legacy fork in subprocess paths.        OBS: C+
	"execve",          // WHY: the Bash tool spawns commands.          OBS: C+
	"wait4",           // WHY: Go's os/exec.Wait.                      OBS: G
	"exit",            // WHY: per-thread exit.                        OBS: G
	"exit_group",      // WHY: whole-process exit.                     OBS: G
	"set_tid_address", // WHY: glibc + Go runtime; required at thread  OBS: G, L
	                   //      bring-up so the kernel clears the TID.
	"set_robust_list", // WHY: pthread_create install per-thread       OBS: L
	                   //      futex robust list (NPTL invariant).
	"rseq",            // WHY: glibc 2.35+ registers rseq per thread for OBS: L
	                   //      restartable sequences (mandatory or thread
	                   //      bring-up fails on modern systems).
	"arch_prctl",      // WHY: Go runtime sets %fs base on x86_64 (TLS). OBS: G (x86_64)
	"prctl",           // WHY: PR_SET_NAME (Go thread names) +          OBS: G
	                   //      PR_GET_DUMPABLE.
	"prlimit64",       // WHY: Go runtime reads RLIMIT_STACK on M startup. OBS: G
	"getrlimit",       // WHY: legacy form on older glibc.              OBS: L

	// --- Identity / system info ---
	"uname",     // WHY: glibc bring-up reads kernel version.        OBS: L
	"getuid",    // WHY: glibc + Go runtime.                         OBS: L, G
	"getgid",    // WHY: glibc + Go runtime.                         OBS: L
	"geteuid",   // WHY: glibc.                                      OBS: L
	"getegid",   // WHY: glibc.                                      OBS: L
	"getresuid", // WHY: glibc; some auth paths read it.             OBS: L
	"getresgid", // WHY: glibc.                                      OBS: L
	"getpid",    // WHY: Go runtime + agent logs.                    OBS: G
	"getppid",   // WHY: peer-cred / parent-check paths.             OBS: G
	"gettid",    // WHY: Go runtime per-M tid; logging.              OBS: G
	"capget",    // WHY: glibc reads caps to decide setuid behavior. OBS: L

	// --- Time ---
	"clock_gettime",   // WHY: Go runtime now-loop, time.Now.       OBS: G
	"clock_nanosleep", // WHY: time.Sleep / select with timeout.    OBS: G
	"nanosleep",       // WHY: legacy variant.                      OBS: G
	"gettimeofday",    // WHY: glibc + some logging libs.           OBS: L

	// --- Random ---
	"getrandom", // WHY: Go crypto/rand, glibc stack canaries.       OBS: G, L

	// --- Sync primitives ---
	"futex",       // WHY: every Go mutex, every pthread mutex.       OBS: G, L
	"sched_yield", // WHY: Go runtime spin-then-yield in lock paths.  OBS: G

	// --- I/O multiplexing ---
	"poll",           // WHY: legacy poll.                                OBS: L
	"ppoll",          // WHY: Go net poller fallback.                     OBS: G
	"epoll_create1",  // WHY: Go netpoll bring-up.                        OBS: G
	"epoll_ctl",      // WHY: Go netpoll add/remove fds.                  OBS: G
	"epoll_wait",     // WHY: Go netpoll wait.                            OBS: G
	"epoll_pwait",    // WHY: modern Go netpoll uses pwait variant.       OBS: G
	"eventfd2",       // WHY: pthread / Go runtime interrupt channel.     OBS: G
	"timerfd_create", // WHY: net/http server idle-conn reaper.           OBS: G

	// --- Network (TCP/UDP to LLM API; unix sockets to host daemon) ---
	"socket",      // WHY: LLM API HTTPS + host daemon unix socket.    OBS: C
	"connect",     // WHY: HTTPS dial; unix-socket dial.               OBS: C
	"sendto",      // WHY: UDP DNS (libc resolver).                    OBS: L
	"recvfrom",    // WHY: UDP DNS replies.                            OBS: L
	"sendmsg",     // WHY: cmsg passing on unix sockets (peer-cred).   OBS: C
	"recvmsg",     // WHY: cmsg receive (peer-cred).                   OBS: C
	"shutdown",    // WHY: orderly close of HTTPS connections.         OBS: C
	"bind",        // WHY: agentjail daemon binds local socket; Go    OBS: G
	               //      net.Listen for tool callbacks.
	"listen",      // WHY: pair with bind.                             OBS: G
	"accept4",     // WHY: modern accept with SOCK_CLOEXEC.            OBS: G
	"getsockname", // WHY: ephemeral-port lookup after bind.           OBS: G
	"getpeername", // WHY: peer identity logging.                      OBS: G
	"setsockopt",  // WHY: SO_REUSEADDR, TCP_NODELAY, SO_KEEPALIVE.    OBS: G
	"getsockopt",  // WHY: SO_ERROR after non-blocking connect.        OBS: G

	// --- Misc ---
	"ioctl", // WHY: TIOCGWINSZ for the agent's TUI;             OBS: C
	         //      FIONREAD on sockets. Note: ioctl is a wide
	         //      surface — a future hardening pass should
	         //      switch this entry to per-cmd argument
	         //      filtering. Tracked in DECISIONS.md.
}

// Default returns a Profile pre-loaded with the Baseline allowlist and
// the production-grade default action (kill process). Callers should
// almost always start here.
func Default() Profile {
	cp := make([]string, len(Baseline))
	copy(cp, Baseline)
	return Profile{
		Allowlist:     cp,
		DefaultAction: ActionKillProcess,
	}
}

// WithExtra returns a copy of p with the named syscalls appended to the
// allowlist. Duplicates are tolerated (the BPF filter does not care).
func (p Profile) WithExtra(names ...string) Profile {
	out := make([]string, 0, len(p.Allowlist)+len(names))
	out = append(out, p.Allowlist...)
	out = append(out, names...)
	return Profile{Allowlist: out, DefaultAction: p.DefaultAction}
}

// WithDefaultAction returns a copy of p with a different default action.
// Exposed for tests; production callers must keep ActionKillProcess.
func (p Profile) WithDefaultAction(a Action) Profile {
	return Profile{Allowlist: append([]string(nil), p.Allowlist...), DefaultAction: a}
}

// Size returns the number of unique syscall names in the allowlist.
func (p Profile) Size() int {
	seen := make(map[string]struct{}, len(p.Allowlist))
	for _, n := range p.Allowlist {
		seen[n] = struct{}{}
	}
	return len(seen)
}
