// Package proxyctl defines the typed control-plane protocol shared between
// agentjail-shield (the registrar) and agentjail-netproxy (the control plane).
//
// One netproxy serves every shielded session on a single localhost port. Each
// session is identified by an unguessable Token, injected as the proxy
// credential (Proxy-Authorization: Basic <token>:) on the data plane. netproxy
// keys a SEPARATE effective allowlist per Token, with NO global fallback, so
// two concurrent sessions with different allowlists never bleed.
//
// The control plane -- registration, fingerprint negotiation, and (Phase 3)
// dynamic grants -- lives on a Unix-domain socket (ControlSocketPath) that the
// sandboxed agent cannot reach: on Linux the socket sits under the read-only
// ~/.agentjail grant, and AF_UNIX connect() requires WRITE access to the socket
// inode (the exact inverse of why ~/.agentjail/daemon.sock needs an explicit
// single-file write grant); on macOS the shield emits an explicit
// (deny network-outbound (literal ...)) for the path. The Token in the agent's
// environment is therefore a DATA-PLANE bearer only -- it authorizes "use this
// session's allowlist" and carries no control/grant power, because the control
// socket is unreachable.
//
// Wire format is JSON at the socket boundary only; every field decodes into the
// typed structs below immediately. Never log a Token or the proxy URL.
//
// This package holds TYPES only -- no net/socket I/O, no landlock/sbpl. The
// server (netproxy) and client (shield) implement their own consumer-defined
// interfaces (ControlPlane / ProxyRegistrar) against these types. See the
// session-aware netproxy control-plane ADR.
package proxyctl

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// ProtocolVersion is the control-plane wire protocol version. It is bumped on
// any incompatible change to the Request/Response shapes or semantics. A shield
// that connects to a running netproxy with an INCOMPATIBLE ProtocolVersion must
// fail closed (refuse to launch), never silently kill the other proxy.
type ProtocolVersion int

// CurrentProtocolVersion is the protocol version this build speaks.
const CurrentProtocolVersion ProtocolVersion = 1

// Token is an unguessable per-session credential. It is the data-plane bearer
// (proxy username) and the control-plane registration key. Treat as a secret:
// never log it, never place it in an audit Detail (fingerprint only).
type Token string

// TokenBytes is the entropy width of a freshly minted Token before encoding.
const TokenBytes = 32

// NewToken mints a cryptographically random Token (TokenBytes of entropy,
// base64url without padding). It returns an error only if the system CSPRNG
// fails, which callers must treat as fatal (fail closed -- do not launch a
// session without a real token).
func NewToken() (Token, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("proxyctl: mint token: %w", err)
	}
	return Token(base64.RawURLEncoding.EncodeToString(b)), nil
}

// Fingerprint identifies a running netproxy so a launching shield can decide
// whether to reuse it. ProtocolVersion governs compatibility (reuse vs. fail
// closed); BinaryVersion is informational -- a shield does NOT restart a proxy
// that is serving other live sessions merely because the binary version bumped.
type Fingerprint struct {
	BinaryVersion   string          `json:"binary_version"`
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
}

// Compatible reports whether a shield speaking want can safely reuse a proxy
// advertising f. Compatibility is protocol-version equality; binary drift is
// tolerated.
func (f Fingerprint) Compatible(want ProtocolVersion) bool {
	return f.ProtocolVersion == want
}

// SessionPolicy is the fully-resolved, per-session enforcement data the shield
// registers with netproxy. AllowedHosts is the effective allowlist for THIS
// session (essentials ++ MCP-derived ++ editable ++ trusted project overlay),
// already computed by the shield; netproxy stores it verbatim under the
// session's Token and matches CONNECT targets against it. There is deliberately
// no global fallback list in netproxy -- an unknown/missing token is denied.
type SessionPolicy struct {
	AllowedHosts []string `json:"allowed_hosts"`
}

// RequestType enumerates the control-plane operations.
type RequestType string

const (
	// ReqFingerprint asks the running proxy to identify itself so the shield
	// can decide reuse vs. fail-closed. No Token required.
	ReqFingerprint RequestType = "fingerprint"
	// ReqRegister leases a session: it binds Token -> Policy for LeaseTTLMs.
	// The lease is reaped on expiry regardless of traffic (macOS cannot
	// deregister post-exec), so a background process cannot keep a token alive
	// by generating traffic.
	ReqRegister RequestType = "register"
	// ReqGrant (Phase 3) additively widens an existing session's allowlist for
	// a bounded TTL. Accepted only over the control socket (unreachable by the
	// agent); the grant verb is additionally denied to agents by command
	// policy. Not wired until Phase 3.
	ReqGrant RequestType = "grant"
	// ReqGrantList lists the pending grant requests netproxy currently holds
	// in memory, across all sessions. Control-socket only. Carries no Token
	// -- callers see the pending set, not who can approve it.
	ReqGrantList RequestType = "grant_list"
	// ReqGrantApprove claims a pending grant request by GrantID and applies it
	// to the owning session's allowlist. Control-socket only; netproxy
	// resolves session->Token from its own in-memory registration -- the
	// caller supplies no Token and no session identity, only the GrantID.
	ReqGrantApprove RequestType = "grant_approve"
	// ReqGrantDeny discards a pending grant request by GrantID without
	// applying it. Control-socket only, same GrantID-only shape as approve.
	ReqGrantDeny RequestType = "grant_deny"
)

// Request is the control-plane request envelope (JSON on the socket).
type Request struct {
	Type RequestType `json:"type"`
	// Token is required for register/grant; omitted for fingerprint.
	Token Token `json:"token,omitempty"`
	// SessionID is a NON-SECRET handle for register (the Claude Code hook
	// session id, or a fresh opaque handle minted by the shield). It exists
	// so a human approving a grant can disambiguate sessions; it carries no
	// authority on its own -- the Token remains the data-plane bearer.
	SessionID string `json:"session_id,omitempty"`
	// Cwd is the session's working directory at register time, for register.
	// Display-only: shown in `agentjail grants` so a human can tell sessions
	// apart. Never used for authorization.
	Cwd string `json:"cwd,omitempty"`
	// Policy is the resolved session policy for register.
	Policy *SessionPolicy `json:"policy,omitempty"`
	// LeaseTTLMs is the hard absolute lease lifetime for register, in
	// milliseconds. The proxy caps it at MaxLeaseTTLMs.
	LeaseTTLMs int64 `json:"lease_ttl_ms,omitempty"`
	// Hosts is the additive host list for grant (Phase 3).
	Hosts []string `json:"hosts,omitempty"`
	// GrantTTLMs is the hard TTL for a grant (Phase 3).
	GrantTTLMs int64 `json:"grant_ttl_ms,omitempty"`
	// GrantID identifies a single pending grant request for grant_approve /
	// grant_deny. This is the ONLY identifying field those two verbs carry --
	// no Token, no session identity -- netproxy resolves session->Token from
	// its own in-memory pending map by GrantID.
	GrantID string `json:"grant_id,omitempty"`
}

// Response is the control-plane response envelope (JSON on the socket).
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Fingerprint is populated on a successful fingerprint response.
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`
	// Grants is populated on a successful grant_list response. It NEVER
	// carries a Token -- see GrantInfo.
	Grants []GrantInfo `json:"grants,omitempty"`
}

// GrantInfo describes one pending grant request for `agentjail grants`. It is
// deliberately Token-less: the list response is safe to print to a human
// terminal and must never leak the session's data-plane bearer.
type GrantInfo struct {
	GrantID string `json:"grant_id"`
	Host    string `json:"host"`
	TTLMs   int64  `json:"ttl_ms"`
	// Cwd is the requesting session's working directory, display-only.
	Cwd string `json:"cwd,omitempty"`
	// Reason is the agent-supplied justification, display-only and bounded
	// by MaxReasonLen.
	Reason string `json:"reason,omitempty"`
}

// MaxControlMsgBytes bounds a single control-plane message (request or
// response) so neither peer can be forced to buffer unbounded data.
// Registration payloads are small (a host list).
const MaxControlMsgBytes = 64 * 1024

// MaxLeaseTTLMs is the hard ceiling netproxy applies to any registration lease
// (24h). A session token is reaped at lease expiry even under continuous
// traffic, bounding the blast radius of a leaked token and preventing an
// agent-spawned background process from keeping a session alive indefinitely.
const MaxLeaseTTLMs int64 = 24 * 60 * 60 * 1000

// Runtime host grant bounds (Phase 3, AGE-93). These cap the sentinel
// endpoint (internal/netproxy) and the CLI so a sandboxed agent cannot exceed
// memory or audit volume by spamming grant requests.
const (
	// MaxReasonLen bounds the agent-supplied --reason string.
	MaxReasonLen = 256
	// MaxGrantTTLMs is the hard ceiling on a single grant's TTL (24h), same
	// horizon as MaxLeaseTTLMs.
	MaxGrantTTLMs int64 = 24 * 60 * 60 * 1000
	// MaxPendingPerSession bounds how many outstanding grant requests a
	// single session may have filed at once.
	MaxPendingPerSession = 16
	// MaxPendingGlobal bounds the total outstanding grant requests across all
	// sessions netproxy is serving.
	MaxPendingGlobal = 256
)
