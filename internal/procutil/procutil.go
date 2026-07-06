// Package procutil provides shared, cross-platform helpers for walking the
// OS process tree. Both the agentjail-hook binary and the daemon need to
// identify an ancestor process (e.g. the long-lived agent process such as
// claude, codex, or cursor) by walking up the parent-PID chain.
package procutil

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
