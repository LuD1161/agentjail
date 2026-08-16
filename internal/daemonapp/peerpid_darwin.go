//go:build darwin

package daemonapp

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procInfoCallPIDInfo      = 0x2
	procPIDVnodePathInfo     = 9
	darwinVnodeInfoSize      = 152
	darwinVnodePathInfoSize  = darwinVnodeInfoSize + unix.PathMax
	darwinVnodePathInfoTotal = 2 * darwinVnodePathInfoSize
)

// darwinVnodeInfo is the opaque prefix of struct vnode_info. Only vip_path is
// relevant to the CWD resolver.
type darwinVnodeInfo [darwinVnodeInfoSize]byte

// darwinVnodeInfoPath mirrors struct vnode_info_path.
type darwinVnodeInfoPath struct {
	vnodeInfo darwinVnodeInfo
	path      [unix.PathMax]byte
}

// darwinProcVnodePathInfo mirrors struct proc_vnodepathinfo.
type darwinProcVnodePathInfo struct {
	cdir darwinVnodeInfoPath
	rdir darwinVnodeInfoPath
}

const darwinCWDPathOffset = darwinVnodeInfoSize

// The syscall buffer must stay ABI-compatible on both supported 64-bit Darwin
// architectures. See ADR 0133-macos-menu-review.
var (
	_ [darwinVnodeInfoSize - int(unsafe.Sizeof(darwinVnodeInfo{}))]byte
	_ [int(unsafe.Sizeof(darwinVnodeInfo{})) - darwinVnodeInfoSize]byte
	_ [darwinVnodePathInfoSize - int(unsafe.Sizeof(darwinVnodeInfoPath{}))]byte
	_ [int(unsafe.Sizeof(darwinVnodeInfoPath{})) - darwinVnodePathInfoSize]byte
	_ [darwinVnodePathInfoTotal - int(unsafe.Sizeof(darwinProcVnodePathInfo{}))]byte
	_ [int(unsafe.Sizeof(darwinProcVnodePathInfo{})) - darwinVnodePathInfoTotal]byte
	_ [darwinCWDPathOffset - int(unsafe.Offsetof(darwinProcVnodePathInfo{}.cdir.path))]byte
	_ [int(unsafe.Offsetof(darwinProcVnodePathInfo{}.cdir.path)) - darwinCWDPathOffset]byte
)

// extractPeerPID returns the PID of the process on the other end of a Unix
// domain socket connection using the macOS LOCAL_PEERPID socket option.
func extractPeerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("extractPeerPID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extractPeerPID: SyscallConn: %w", err)
	}

	var pid int
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		pid, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, fmt.Errorf("extractPeerPID: Control: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("extractPeerPID: getsockopt LOCAL_PEERPID: %w", sysErr)
	}
	return pid, nil
}

// extractPeerUID returns the UID of the process on the other end of a Unix
// domain socket connection using the macOS LOCAL_PEERCRED socket option
// (xucred.cr_uid). Populated by the kernel at connect/accept time, so it
// cannot be spoofed by the connecting process.
func extractPeerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("extractPeerUID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extractPeerUID: SyscallConn: %w", err)
	}

	var xucred *unix.Xucred
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		xucred, sysErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("extractPeerUID: Control: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("extractPeerUID: getsockopt LOCAL_PEERCRED: %w", sysErr)
	}
	return int(xucred.Uid), nil
}

func resolvePeerCWD(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("resolvePeerCWD: invalid pid %d", pid)
	}

	var info darwinProcVnodePathInfo
	want := unsafe.Sizeof(info)
	n, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		procInfoCallPIDInfo,
		uintptr(pid),
		procPIDVnodePathInfo,
		0,
		uintptr(unsafe.Pointer(&info)),
		want,
	)
	runtime.KeepAlive(&info)
	if errno != 0 {
		return "", fmt.Errorf("resolvePeerCWD: proc_info pid %d: %w", pid, errno)
	}
	if n != want {
		return "", fmt.Errorf("resolvePeerCWD: proc_info pid %d returned %d bytes, want %d", pid, n, want)
	}

	return decodeDarwinCWD(info.cdir.path)
}

func decodeDarwinCWD(path [unix.PathMax]byte) (string, error) {
	end := 0
	for end < len(path) && path[end] != 0 {
		end++
	}
	if end == len(path) {
		return "", fmt.Errorf("resolvePeerCWD: vnode path is not NUL-terminated")
	}
	if end == 0 {
		return "", fmt.Errorf("resolvePeerCWD: vnode path is empty")
	}

	cwd := string(path[:end])
	if !utf8.ValidString(cwd) {
		return "", fmt.Errorf("resolvePeerCWD: vnode path is not valid UTF-8")
	}
	if !filepath.IsAbs(cwd) {
		return "", fmt.Errorf("resolvePeerCWD: vnode path is not absolute: %q", cwd)
	}

	cwd = filepath.Clean(cwd)
	if !filepath.IsAbs(cwd) {
		return "", fmt.Errorf("resolvePeerCWD: cleaned vnode path is not absolute: %q", cwd)
	}
	return cwd, nil
}
