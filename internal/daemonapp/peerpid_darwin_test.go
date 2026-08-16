//go:build darwin

package daemonapp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestResolvePeerCWD_Self(t *testing.T) {
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	got, err := resolvePeerCWD(os.Getpid())
	if err != nil {
		t.Fatalf("resolvePeerCWD: %v", err)
	}
	if got != want {
		t.Errorf("resolvePeerCWD(self) = %q, want %q", got, want)
	}
}

func TestResolvePeerCWD_Child(t *testing.T) {
	if os.Getenv("AGENTJAIL_PEER_CWD_CHILD") == "1" {
		if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
			t.Fatalf("signal parent: %v", err)
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}

	childDir := filepath.Join(t.TempDir(), "cwd with café")
	if err := os.Mkdir(childDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestResolvePeerCWD_Child$")
	cmd.Dir = childDir
	cmd.Env = append(os.Environ(), "AGENTJAIL_PEER_CWD_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read child readiness: %v", err)
	}
	if strings.TrimSpace(line) != "ready" {
		t.Fatalf("child readiness = %q, want ready", line)
	}

	got, err := resolvePeerCWD(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("resolvePeerCWD(child): %v", err)
	}
	if want := filepath.Clean(childDir); got != want {
		t.Errorf("resolvePeerCWD(child) = %q, want %q", got, want)
	}
}

func TestResolvePeerCWD_InvalidOrExitedPID(t *testing.T) {
	for _, pid := range []int{0, -1, 1 << 30} {
		if _, err := resolvePeerCWD(pid); err == nil {
			t.Errorf("resolvePeerCWD(%d) succeeded", pid)
		}
	}

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run child: %v", err)
	}
	if _, err := resolvePeerCWD(cmd.Process.Pid); err == nil {
		t.Errorf("resolvePeerCWD(exited pid %d) succeeded", cmd.Process.Pid)
	}
}

func TestResolvePeerCWD_OtherUserPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root does not exercise another user's permission boundary")
	}
	_, err := resolvePeerCWD(1)
	if err == nil {
		t.Log("host permits resolving PID 1 CWD; no permission failure is available")
		return
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Logf("host denied PID 1 CWD lookup: %v", err)
		return
	}
	t.Logf("PID 1 CWD lookup failed without a permission error: %v", err)
}

func TestDecodeDarwinCWD(t *testing.T) {
	valid := func(s string) [unix.PathMax]byte {
		var path [unix.PathMax]byte
		copy(path[:], s)
		return path
	}

	noNUL := valid("")
	for i := range noNUL {
		noNUL[i] = 'x'
	}
	invalidUTF8 := valid("")
	invalidUTF8[0] = 0xff
	invalidUTF8[1] = 0

	cases := []struct {
		name    string
		path    [unix.PathMax]byte
		want    string
		wantErr bool
	}{
		{name: "clean absolute", path: valid("/tmp/../project"), want: "/project"},
		{name: "relative", path: valid("project"), wantErr: true},
		{name: "empty", path: valid(""), wantErr: true},
		{name: "invalid UTF-8", path: invalidUTF8, wantErr: true},
		{name: "missing NUL", path: noNUL, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeDarwinCWD(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeDarwinCWD(%q) succeeded", tc.path[:])
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeDarwinCWD: %v", err)
			}
			if got != tc.want {
				t.Errorf("decodeDarwinCWD = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDarwinProcVnodePathInfoLayout(t *testing.T) {
	if runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		t.Fatalf("unsupported Darwin architecture %q", runtime.GOARCH)
	}
	if got := unsafe.Sizeof(darwinVnodeInfo{}); got != darwinVnodeInfoSize {
		t.Errorf("vnode_info size = %d, want %d", got, darwinVnodeInfoSize)
	}
	if got := unsafe.Sizeof(darwinVnodeInfoPath{}); got != darwinVnodePathInfoSize {
		t.Errorf("vnode_info_path size = %d, want %d", got, darwinVnodePathInfoSize)
	}
	if got := unsafe.Sizeof(darwinProcVnodePathInfo{}); got != darwinVnodePathInfoTotal {
		t.Errorf("proc_vnodepathinfo size = %d, want %d", got, darwinVnodePathInfoTotal)
	}
	if got := unsafe.Offsetof(darwinProcVnodePathInfo{}.cdir.path); got != darwinCWDPathOffset {
		t.Errorf("pvi_cdir.vip_path offset = %d, want %d", got, darwinCWDPathOffset)
	}
}
