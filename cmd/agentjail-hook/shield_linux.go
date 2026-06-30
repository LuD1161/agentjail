//go:build linux

package main

import (
	"os"
	"strings"
)

// checkNoNewPrivs reads /proc/self/status and returns true if NoNewPrivs is
// set to 1, which is a prerequisite for Landlock (the shield enables it).
func checkNoNewPrivs() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:"))
			return val == "1"
		}
	}
	return false
}
