//go:build darwin

package procutil

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func readComm(pid int) string {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
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

func readPPID(pid int) int {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0
	}
	return int(info.Eproc.Ppid)
}

func readStartMarker(pid int) (StartMarker, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	tv := info.Proc.P_starttime
	return StartMarker(uint64(tv.Sec)*1_000_000 + uint64(tv.Usec)), nil
}

func currentStartMarker() (StartMarker, error) {
	return StartMarker(time.Now().UnixMicro()), nil
}
