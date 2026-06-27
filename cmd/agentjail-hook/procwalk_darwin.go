//go:build darwin

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

func readProcessComm(pid int) string {
	info, err := unix.SysctlKinfoProc(fmt.Sprintf("kern.proc.pid.%d", pid))
	if err != nil {
		return ""
	}
	comm := info.Proc.P_comm
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return strings.TrimSpace(string(comm[:n]))
}

func readProcessPPID(pid int) int {
	info, err := unix.SysctlKinfoProc(fmt.Sprintf("kern.proc.pid.%d", pid))
	if err != nil {
		return 0
	}
	return int(info.Eproc.Ppid)
}
