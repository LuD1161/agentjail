//go:build darwin && !cgo

package proctree

// Pure-Go macOS implementation. Shells out to `ps -o ppid= -p <pid>`;
// one fork per call but only hit on the peer-auth path, which is <1 Hz
// per cred op. A follow-up commit adds the cgo libproc.proc_pidinfo
// path which will replace this body via a //go:linkname or build-tag
// swap; the pure-Go fallback remains for CGO_ENABLED=0 builds.

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func parentOf(pid int) (int, error) {
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, fmt.Errorf("proctree: ps for pid=%d: %w", pid, err)
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, fmt.Errorf("proctree: no ppid for pid=%d", pid)
	}
	ppid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("proctree: parse ppid %q for pid=%d: %w", s, pid, err)
	}
	return ppid, nil
}
