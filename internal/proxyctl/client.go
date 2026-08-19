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
// proxy clamps it to MaxLeaseTTLMs). ctlToken must be read before Landlock is
// applied (ADR 0067). sessionID and cwd are non-secret,
// display-only identity for the session (see Request.SessionID / Request.Cwd)
// so a human approving a grant later can tell sessions apart; neither carries
// authority. It returns an error if the proxy refuses.
func Register(sockPath, ctlToken string, tok Token, sessionID, cwd string, pol SessionPolicy, leaseTTL, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{
		Type:       ReqRegister,
		CtlToken:   ctlToken,
		Token:      tok,
		SessionID:  sessionID,
		Cwd:        cwd,
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

// GrantList lists the pending grant requests netproxy currently holds, across
// all sessions, over the control socket owning sockPath. The result never
// contains a Token (see GrantInfo).
func GrantList(sockPath, ctlToken string, timeout time.Duration) ([]GrantInfo, error) {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantList, CtlToken: ctlToken}, timeout)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("grant list refused: %s", resp.Error)
	}
	return resp.Grants, nil
}

// GrantApprove claims the pending grant request identified by grantID and
// applies it to its owning session's allowlist. It supplies no Token and no
// session identity -- netproxy resolves session->Token from its own
// in-memory pending map by grantID.
func GrantApprove(sockPath, ctlToken, grantID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantApprove, CtlToken: ctlToken, GrantID: grantID}, timeout)
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
func GrantDeny(sockPath, ctlToken, grantID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantDeny, CtlToken: ctlToken, GrantID: grantID}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("grant deny refused: %s", resp.Error)
	}
	return nil
}

func InstallConnector(sockPath, ctlToken string, route ConnectorRoute, timeout time.Duration) error {
	return connectorRoute(sockPath, ctlToken, ReqConnectorInstall, route, timeout)
}

func RemoveConnector(sockPath, ctlToken, sessionID, connectorID string, timeout time.Duration) error {
	return connectorRoute(sockPath, ctlToken, ReqConnectorRemove, ConnectorRoute{SessionID: sessionID, ConnectorID: connectorID}, timeout)
}

func RegisterConnectorCapability(sockPath, ctlToken string, token Token, capability string, route ConnectorRoute, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqConnectorCapabilityRegister, CtlToken: ctlToken, Token: token, ConnectorCapability: capability, Connector: &route}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("connector capability refused: %s", resp.Error)
	}
	return nil
}

func UseConnectorCapability(sockPath, capability, sessionID, connectorID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqConnectorCapabilityUse, ConnectorCapability: capability, Connector: &ConnectorRoute{SessionID: sessionID, ConnectorID: connectorID}}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("connector capability refused: %s", resp.Error)
	}
	return nil
}

func RemoveConnectorCapability(sockPath, capability, sessionID, connectorID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqConnectorCapabilityRemove, ConnectorCapability: capability, Connector: &ConnectorRoute{SessionID: sessionID, ConnectorID: connectorID}}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("connector capability refused: %s", resp.Error)
	}
	return nil
}

func connectorRoute(sockPath, ctlToken string, typ RequestType, route ConnectorRoute, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: typ, CtlToken: ctlToken, Connector: &route}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("connector route refused: %s", resp.Error)
	}
	return nil
}
