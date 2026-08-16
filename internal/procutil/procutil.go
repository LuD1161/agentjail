// Package procutil provides shared, cross-platform helpers for walking the
// OS process tree. Both the agentjail-hook binary and the daemon need to
// identify an ancestor process (e.g. the long-lived agent process such as
// claude, codex, or cursor) by walking up the parent-PID chain.
package procutil

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// commTruncateLen is the longest comm the kernel will report. Linux caps
// /proc/<pid>/comm at 15 bytes (TASK_COMM_LEN-1) and Darwin's p_comm is
// similarly bounded, so any process name at or beyond this length is only
// ever observable as a prefix.
const commTruncateLen = 15

// Virtualized wall clocks can pause while the monotonic deadline advances.
// See docs/GOTCHAS.md#80-virtual-wall-clock-stalls.
const startBoundaryAdvanceTimeout = time.Second

// CommMatches reports whether the kernel-reported comm of a process refers to
// the binary named want.
//
// It exists because a name like "agentjail-daemon" (16 bytes) is NEVER
// reported verbatim on Linux — comm is "agentjail-daemo". A plain equality
// check against the full name silently matches nothing, so callers must
// compare through this function rather than against comm directly.
//
// A truncated comm is accepted only at exactly the kernel's cap, so this
// stays a truncation rule and not a loose prefix match ("a" never matches).
func CommMatches(comm, want string) bool {
	if comm == "" || want == "" {
		return false
	}
	if comm == want {
		return true
	}
	return len(comm) >= commTruncateLen && len(comm) < len(want) && strings.HasPrefix(want, comm)
}

// PIDHasComm reports whether pid is a live process whose comm refers to the
// binary named want. Returns false if the process is gone or unreadable.
func PIDHasComm(pid int, want string) bool {
	return CommMatches(readComm(pid), want)
}

// ReadProcessComm returns the command name (comm) for the given PID, or ""
// if it cannot be determined. The implementation is platform-specific.
func ReadProcessComm(pid int) string {
	return readComm(pid)
}

// ReadProcessPPID returns the parent PID for the given PID, or 0 if it
// cannot be determined. The implementation is platform-specific.
func ReadProcessPPID(pid int) int {
	return readPPID(pid)
}

// StartMarker is an OS-monotonic process birth marker. Values are comparable
// only on the same host and boot.
type StartMarker uint64

func ReadProcessStartMarker(pid int) (StartMarker, error) {
	if pid <= 1 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	return readStartMarker(pid)
}

// NextStartBoundary returns a marker strictly after all processes that existed
// when it was called. It waits for the platform marker quantum to advance so a
// later child cannot share a birth bucket with a pre-approval process.
func NextStartBoundary() (StartMarker, error) {
	initial, err := currentStartMarker()
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(startBoundaryAdvanceTimeout)
	for time.Now().Before(deadline) {
		current, err := currentStartMarker()
		if err != nil {
			return 0, err
		}
		if current > initial {
			return current, nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, fmt.Errorf("process start marker did not advance")
}

// DescendantChainStartedAtOrAfter verifies that every process below ancestor
// in pid's ancestry was born at or after boundary.
func DescendantChainStartedAtOrAfter(pid, ancestor int, boundary StartMarker) bool {
	if pid <= 1 || ancestor <= 1 || boundary == 0 {
		return false
	}
	for i := 0; i < 20 && pid > 1; i++ {
		if pid == ancestor {
			return true
		}
		started, err := ReadProcessStartMarker(pid)
		if err != nil || started < boundary {
			return false
		}
		parent := readPPID(pid)
		if parent <= 1 || parent == pid {
			return false
		}
		pid = parent
	}
	return false
}

// Alive reports whether a process with the given PID currently exists. It
// sends signal 0, which performs the kernel's permission/existence check
// without delivering a signal. A non-positive PID is never alive.
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// FindAncestorPID walks up the process tree starting at startPID, calling
// match(pid) at each level (including startPID itself). It returns the
// first PID for which match returns true, and true. If no ancestor matches
// within 20 levels (or the walk reaches PID 1 / a cycle), it returns
// (0, false).
func FindAncestorPID(startPID int, match func(pid int) bool) (int, bool) {
	pid := startPID
	if pid <= 1 {
		return 0, false
	}

	// Walk up to 20 levels to avoid infinite loops on circular proc trees.
	for i := 0; i < 20 && pid > 1; i++ {
		if match(pid) {
			return pid, true
		}
		ppid := readPPID(pid)
		if ppid <= 1 || ppid == pid {
			break
		}
		pid = ppid
	}

	return 0, false
}
