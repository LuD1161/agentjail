package main

import "os"

// findAgentPID walks up the process tree from our parent to find the
// long-lived agent process (claude, codex, cursor). Returns the PID of the
// first ancestor whose comm name matches a known agent, or falls back to
// the topmost non-init ancestor.
func findAgentPID() int {
	pid := os.Getppid()
	if pid <= 1 {
		return pid
	}

	agentNames := map[string]bool{
		"claude": true,
		"codex":  true,
		"cursor": true,
		"aider":  true,
	}

	// Walk up to 20 levels to avoid infinite loops on circular proc trees.
	for i := 0; i < 20 && pid > 1; i++ {
		comm := readProcessComm(pid)
		if agentNames[comm] {
			return pid
		}
		ppid := readProcessPPID(pid)
		if ppid <= 1 || ppid == pid {
			break
		}
		pid = ppid
	}

	// Fallback: return our direct parent.
	return os.Getppid()
}
