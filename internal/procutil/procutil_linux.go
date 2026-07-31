//go:build linux

package procutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readComm(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readPPID(pid int) int {
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

func readStartMarker(pid int) (StartMarker, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	// The second field is parenthesized comm and may contain spaces. Fields
	// after its final ')' start at stat field 3; starttime is field 22.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, fmt.Errorf("malformed /proc stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("short /proc stat")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return StartMarker(ticks), err
}

func currentStartMarker() (StartMarker, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	// Linux exposes process starttime in USER_HZ ticks; USER_HZ is a stable
	// userspace ABI value of 100 on supported Linux architectures.
	return StartMarker(seconds * 100), nil
}
