package procutil

import (
	"os"
	"os/exec"
	"testing"
)

func TestReadProcessComm_Self(t *testing.T) {
	comm := ReadProcessComm(os.Getpid())
	if comm == "" {
		t.Fatalf("expected non-empty comm for self, got empty string")
	}
}

func TestReadProcessPPID_Self(t *testing.T) {
	ppid := ReadProcessPPID(os.Getpid())
	if ppid <= 0 {
		t.Fatalf("expected positive ppid for self, got %d", ppid)
	}
}

func TestFindAncestorPID_FindsSelf(t *testing.T) {
	self := os.Getpid()
	pid, ok := FindAncestorPID(self, func(p int) bool {
		return p == self
	})
	if !ok {
		t.Fatalf("expected to find self PID %d", self)
	}
	if pid != self {
		t.Fatalf("expected pid %d, got %d", self, pid)
	}
}

func TestFindAncestorPID_NotFound(t *testing.T) {
	pid, ok := FindAncestorPID(os.Getpid(), func(p int) bool {
		return false
	})
	if ok {
		t.Fatalf("expected no match, got pid %d", pid)
	}
}

func TestDescendantChainStartedAtOrAfter(t *testing.T) {
	self := os.Getpid()
	boundary, err := NextStartBoundary()
	if err != nil {
		t.Fatalf("NextStartBoundary: %v", err)
	}
	if DescendantChainStartedAtOrAfter(self, os.Getppid(), boundary) {
		t.Fatal("process that predates boundary was accepted")
	}

	child := exec.Command("sleep", "1")
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	if !DescendantChainStartedAtOrAfter(child.Process.Pid, self, boundary) {
		t.Fatal("fresh child process was not accepted below recorded ancestor")
	}
}
