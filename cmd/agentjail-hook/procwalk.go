package main

import (
	"os"
	"strconv"
	"strings"
)

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
		comm := readProcComm(pid)
		if agentNames[comm] {
			return pid
		}
		ppid := readProcPPID(pid)
		if ppid <= 1 || ppid == pid {
			break
		}
		pid = ppid
	}

	// Fallback: return our direct parent.
	return os.Getppid()
}

// readProcComm reads /proc/<pid>/comm (the short process name, max 15 chars).
func readProcComm(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readProcPPID reads the parent PID from /proc/<pid>/status.
func readProcPPID(pid int) int {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			ppid, _ := strconv.Atoi(val)
			return ppid
		}
	}
	return 0
}
