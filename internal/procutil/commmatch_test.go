package procutil

import (
	"os"
	"testing"
)

// CommMatches must accept the kernel's truncated form. Linux caps
// /proc/<pid>/comm at 15 bytes, so the 16-byte "agentjail-daemon" is only ever
// observable as "agentjail-daemo" — a plain equality check matches nothing and
// silently breaks daemon reload.
func TestCommMatchesHandlesKernelTruncation(t *testing.T) {
	const want = "agentjail-daemon"
	cases := []struct {
		comm string
		ok   bool
		why  string
	}{
		{"agentjail-daemon", true, "exact name (untruncated platforms)"},
		{"agentjail-daemo", true, "Linux 15-byte truncation — the real observed value"},
		{"", false, "unreadable comm"},
		{"agentjail", false, "shorter, unrelated binary must not match"},
		{"a", false, "a loose prefix rule would wrongly accept this"},
		{"agentjail-hook", false, "sibling binary"},
		{"agentjail.test", false, "test binary"},
		{"go", false, "a `go build -o .../agentjail-daemon` process"},
		{"agentjail-daemonx", false, "longer name is not this binary"},
	}
	for _, c := range cases {
		if got := CommMatches(c.comm, want); got != c.ok {
			t.Errorf("CommMatches(%q, %q) = %v, want %v — %s", c.comm, want, got, c.ok, c.why)
		}
	}
}

func TestCommMatchesEmptyWant(t *testing.T) {
	if CommMatches("anything", "") {
		t.Error("empty want must never match")
	}
}

// The test binary is not the daemon — the guard that stops `agentjail policy`
// from SIGHUPing whatever pgrep -f happened to match first.
func TestPIDHasCommRejectsSelf(t *testing.T) {
	if PIDHasComm(os.Getpid(), "agentjail-daemon") {
		t.Errorf("test process (comm=%q) misidentified as the daemon", ReadProcessComm(os.Getpid()))
	}
}

func TestPIDHasCommDeadPID(t *testing.T) {
	if PIDHasComm(-1, "agentjail-daemon") {
		t.Error("invalid pid must not match")
	}
}
