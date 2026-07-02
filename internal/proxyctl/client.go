package proxyctl

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

// QueryFingerprint asks the proxy owning sockPath to identify itself. A dial
// error means no proxy is serving that socket (caller decides start-fresh vs.
// fail-closed); a non-OK response is a protocol error.
func QueryFingerprint(sockPath string, timeout time.Duration) (*Fingerprint, error) {
	resp, err := roundTrip(sockPath, Request{Type: ReqFingerprint}, timeout)
	if err != nil {
		return nil, err
	}
	if !resp.OK || resp.Fingerprint == nil {
		return nil, fmt.Errorf("fingerprint refused: %s", resp.Error)
	}
	return resp.Fingerprint, nil
}

// Register leases tok -> pol on the proxy owning sockPath for leaseTTL (the
// proxy clamps it to MaxLeaseTTLMs). It returns an error if the proxy refuses.
func Register(sockPath string, tok Token, pol SessionPolicy, leaseTTL, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{
		Type:       ReqRegister,
		Token:      tok,
		Policy:     &pol,
		LeaseTTLMs: leaseTTL.Milliseconds(),
	}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("register refused: %s", resp.Error)
	}
	return nil
}
