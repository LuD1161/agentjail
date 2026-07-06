package main

import (
	"os"

	"github.com/LuD1161/agentjail/internal/procutil"
)

// findAgentPID walks up the process tree from our parent to find the
// long-lived agent process (claude, codex, cursor). Returns the PID of the
// first ancestor whose comm name matches a known agent, or falls back to
// the topmost non-init ancestor.
func findAgentPID() int {
	agentNames := map[string]bool{
		"claude": true,
		"codex":  true,
		"cursor": true,
		"aider":  true,
	}

	pid, ok := procutil.FindAncestorPID(os.Getppid(), func(p int) bool {
		return agentNames[procutil.ReadProcessComm(p)]
	})
	if ok {
		return pid
	}

	// Fallback: return our direct parent.
	return os.Getppid()
}
