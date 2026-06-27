//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func readProcessComm(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcessPPID(pid int) int {
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
