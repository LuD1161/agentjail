// Single-instance guard for the agent socket.
//
// Exactly one agentjail-daemon may own daemon.sock at a time, regardless of
// how it was installed (Homebrew vs curl) or started (service vs manual). This
// mirrors the flock + probe-before-remove pattern already used by the grant
// control socket (grantserver.go) and the netproxy (control.go); the main
// agent socket was the one bind site that lacked it.
package daemonapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/wire"
)

const (
	// instanceLockName is the flock'd lockfile that serializes single-instance
	// ownership. It lives BESIDE the socket (filepath.Dir(*socketPath)), never
	// hard-coded to ~/.agentjail, so a custom --socket daemon gets its own lock
	// and tests stay isolated.
	instanceLockName = "daemon.lock"
	// instanceLockRetries / instanceLockInterval bound how long we wait for the
	// lock before concluding a live daemon owns it (~1s). This absorbs the
	// brief handoff during a supervised restart where the predecessor is still
	// closing its lock fd.
	instanceLockRetries  = 10
	instanceLockInterval = 100 * time.Millisecond
)

// acquireInstanceLock takes an exclusive, non-blocking flock on lockPath,
// retrying up to `retries` times (sleeping `interval` between attempts) to
// absorb a supervised-restart handoff. On success it returns the held *os.File
// - the caller MUST keep it alive for the process lifetime; the flock releases
// only when the fd closes (process exit or crash). If another holder keeps the
// lock through the retries it returns (nil, false, nil): the caller stands down
// (return 0). If the lockfile cannot be opened it returns (nil, false, err): the
// caller treats this as fatal (return 1).
func acquireInstanceLock(lockPath string, retries int, interval time.Duration) (*os.File, bool, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open instance lock %s: %w", lockPath, err)
	}
	for attempt := 0; ; attempt++ {
		if flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); flockErr == nil {
			return f, true, nil
		}
		if attempt >= retries {
			_ = f.Close()
			return nil, false, nil
		}
		time.Sleep(interval)
	}
}

const pingProbeTimeout = 200 * time.Millisecond

// probeResult classifies what (if anything) holds a socket path.
type probeResult int

const (
	probeNoListener   probeResult = iota // dial failed - stale socket, safe to remove
	probeHealthy                         // valid ControlOpPing reply - live agentjail daemon
	probeUnresponsive                    // connected but no valid ping - foreign/wedged squatter
)

// probeSocket reports what holds socketPath. It dials, sends a ControlOpPing,
// and requires a well-formed ControlResponse{OK:true} within pingProbeTimeout.
// A bare successful connect() is deliberately NOT treated as "live": only a
// valid ping proves a responsive agentjail daemon.
func probeSocket(socketPath string) probeResult {
	conn, err := net.DialTimeout("unix", socketPath, pingProbeTimeout)
	if err != nil {
		return probeNoListener
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(pingProbeTimeout))
	if err := json.NewEncoder(conn).Encode(wire.ControlRequest{Type: wire.ControlType, Op: wire.ControlOpPing}); err != nil {
		return probeUnresponsive
	}
	var resp wire.ControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil || !resp.OK {
		return probeUnresponsive
	}
	return probeHealthy
}

// bindAgentSocket binds socketPath, replacing the old blind os.Remove +
// net.Listen. It stats the path; if occupied it probes it: a healthy agentjail
// daemon -> stand down (nil, false, nil); an unresponsive squatter -> error
// (never unlink a socket something holds); no listener -> remove the stale file
// and bind. A losing EADDRINUSE race (someone bound between probe and listen)
// -> stand down. The caller holds the instance flock, so no guard-aware daemon
// races here; this closes the pre-guard/foreign gaps.
func bindAgentSocket(socketPath string) (net.Listener, bool, error) {
	if _, statErr := os.Stat(socketPath); statErr == nil {
		switch probeSocket(socketPath) {
		case probeHealthy:
			return nil, false, nil
		case probeUnresponsive:
			return nil, false, fmt.Errorf("socket %s is held by an unresponsive non-agentjail process; refusing to unlink it", socketPath)
		case probeNoListener:
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				return nil, false, fmt.Errorf("remove stale socket %s: %w", socketPath, err)
			}
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("bind agent socket %s: %w", socketPath, err)
	}
	return ln, true, nil
}
