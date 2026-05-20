//go:build linux

package proctree

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// parentOf reads /proc/<pid>/stat and returns the 4th field (ppid). We
// parse from the END of the comm field because the comm may contain
// arbitrary characters (including spaces and parens) wrapped in '(' ')'.
func parentOf(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("proctree: read stat for pid=%d: %w", pid, err)
	}
	s := string(data)
	// stat format: "PID (comm) STATE PPID ..."; comm may contain spaces
	// and ')' so locate the LAST ')' to split comm from the rest.
	close := strings.LastIndexByte(s, ')')
	if close < 0 || close+1 >= len(s) {
		return 0, fmt.Errorf("proctree: malformed stat for pid=%d", pid)
	}
	rest := strings.Fields(s[close+1:])
	if len(rest) < 2 {
		return 0, fmt.Errorf("proctree: stat short for pid=%d", pid)
	}
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return 0, fmt.Errorf("proctree: parse ppid for pid=%d: %w", pid, err)
	}
	return ppid, nil
}
