package seccomp

// KnownNames is the union of every syscall name we recognise across
// supported architectures (x86_64 + aarch64).
//
// It exists so the compile-time resolver can distinguish two failure
// modes for an allowlist entry:
//
//   - typo / never-existed name  -> hard error (fail-closed)
//   - exists on another arch but
//     not the running one         -> silent skip (the syscall is
//                                    genuinely uncallable here)
//
// See profile_linux.go compile() for the resolution rule.
//
// Maintenance: when you add a name to Baseline that's truly new (not
// previously known on any arch we ship), ALSO add it here. The
// platform-independent test profile_test.go asserts coverage:
// every Baseline name appears in KnownNames.
var KnownNames = map[string]struct{}{
	// File I/O
	"read": {}, "write": {}, "open": {}, "openat": {}, "openat2": {},
	"close": {}, "lseek": {}, "pread64": {}, "pwrite64": {},
	"readv": {}, "writev": {},
	"stat": {}, "fstat": {}, "lstat": {}, "newfstatat": {}, "statx": {},
	"access": {}, "faccessat2": {},
	"readlink": {}, "readlinkat": {},
	"getcwd": {}, "getdents64": {}, "fcntl": {},
	"dup": {}, "dup2": {}, "dup3": {}, "pipe2": {}, "umask": {},
	"fstatfs": {}, "chdir": {}, "fchdir": {},

	// Memory
	"mmap": {}, "munmap": {}, "mprotect": {}, "brk": {},
	"madvise": {}, "memfd_create": {},

	// Signals
	"rt_sigaction": {}, "rt_sigprocmask": {}, "rt_sigreturn": {},
	"sigaltstack": {}, "kill": {}, "tkill": {}, "tgkill": {},
	"pidfd_send_signal": {},

	// Process lifecycle
	"clone": {}, "clone3": {}, "fork": {}, "execve": {}, "wait4": {},
	"exit": {}, "exit_group": {},
	"set_tid_address": {}, "set_robust_list": {}, "rseq": {},
	"arch_prctl": {}, "prctl": {}, "prlimit64": {}, "getrlimit": {},

	// Identity
	"uname": {}, "getuid": {}, "getgid": {}, "geteuid": {}, "getegid": {},
	"getresuid": {}, "getresgid": {},
	"getpid": {}, "getppid": {}, "gettid": {}, "capget": {},

	// Time
	"clock_gettime": {}, "clock_nanosleep": {}, "nanosleep": {},
	"gettimeofday": {},

	// Random
	"getrandom": {},

	// Sync
	"futex": {}, "sched_yield": {},

	// I/O multiplexing
	"poll": {}, "ppoll": {},
	"epoll_create1": {}, "epoll_ctl": {}, "epoll_wait": {}, "epoll_pwait": {},
	"eventfd2": {}, "timerfd_create": {},

	// Network
	"socket": {}, "connect": {}, "sendto": {}, "recvfrom": {},
	"sendmsg": {}, "recvmsg": {}, "shutdown": {},
	"bind": {}, "listen": {}, "accept4": {},
	"getsockname": {}, "getpeername": {},
	"setsockopt": {}, "getsockopt": {},

	// Misc
	"ioctl": {},
}
