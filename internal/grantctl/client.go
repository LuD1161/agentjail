package grantctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// roundTrip sends one request over the control socket and reads one response.
// It never retries and never blocks longer than timeout.
func roundTrip(sockPath string, req Request, timeout time.Duration) (Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("send control request: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, MaxControlMsgBytes)).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("read control response: %w", err)
	}
	return resp, nil
}

// GrantRequest files a new runtime host grant request on the daemon. The daemon
// assigns a GrantID, queues it, and returns the ID to the caller so it can poll
// or wait for approval. sessionID and cwd are non-secret, display-only identity
// for the session (see Request.SessionID / Request.CWD) so a human approving a
// grant later can tell sessions apart; neither carries authority.
func GrantRequest(sockPath string, sessionID, cwd, host string, ttlMs int64, reason string, timeout time.Duration) (string, error) {
	resp, err := roundTrip(sockPath, Request{
		Type:      ReqGrantRequest,
		SessionID: sessionID,
		CWD:       cwd,
		Host:      host,
		TTLMs:     ttlMs,
		Reason:    reason,
	}, timeout)
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("grant request refused: %s", resp.Error)
	}
	return resp.GrantID, nil
}

// GrantList lists the pending grant requests the daemon currently holds, across
// all sessions. The result never contains a Token (see GrantInfo).
func GrantList(sockPath string, timeout time.Duration) ([]GrantInfo, error) {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantList}, timeout)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("grant list refused: %s", resp.Error)
	}
	return resp.Grants, nil
}

// GrantApprove claims the pending grant request identified by grantID and
// applies it to its owning session's allowlist. The daemon resolves
// SessionID/CWD from its own in-memory grant map by GrantID.
func GrantApprove(sockPath, grantID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantApprove, GrantID: grantID}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("grant approve refused: %s", resp.Error)
	}
	return nil
}

// GrantDeny discards the pending grant request identified by grantID without
// applying it. Same GrantID-only shape as GrantApprove.
func GrantDeny(sockPath, grantID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantDeny, GrantID: grantID}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("grant deny refused: %s", resp.Error)
	}
	return nil
}

// RefusedError reports that the round trip COMPLETED and the daemon answered
// ok=false. It is distinct from a transport error on purpose: "the daemon
// rejected your policy" and "no daemon answered" demand opposite responses from
// the caller (surface the reason vs. fall back to another delivery path), and
// collapsing both into one error is how a rejected policy gets silently retried
// as a success.
type RefusedError struct {
	Op     RequestType
	Reason string
}

func (e *RefusedError) Error() string {
	return string(e.Op) + " refused: " + e.Reason
}

// DaemonReload asks the daemon on sockPath (the privileged control socket) to
// reload policy.yaml and recompile the Rego bundle. A *RefusedError carries the
// compile error verbatim when the new rules are rejected -- the daemon keeps the
// old bundle in that case, so the caller must surface it rather than assume the
// edit took effect. Any other error means the daemon could not be reached.
//
// sockPath must be the privileged control socket, never the agent-facing
// daemon.sock: reload is a full Rego recompile, and the agent can reach that
// socket by design, which made it a fail-open DoS lever (ADR 0066).
func DaemonReload(sockPath string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqDaemonReload}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return &RefusedError{Op: ReqDaemonReload, Reason: resp.Error}
	}
	return nil
}

// IsAvailable probes the socket at sockPath with a short dial timeout and
// returns true if the socket is connectable, false otherwise. A false result
// means no daemon is serving that socket (caller decides start-fresh vs.
// fail-closed).
func IsAvailable(sockPath string) bool {
	conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
