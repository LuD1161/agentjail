// Package v1 is the FROZEN wire contract for the agentpolicy decision RPC.
//
// This package defines the JSON-line message shapes the per-session daemon
// (agentjail track) exchanges with the agentpolicy decision engine over the
// existing Unix socket. The shape was first shipped in commit 264eadd
// ("feat(daemon): sync decision RPC over the existing socket") and is
// promoted here to a versioned, byte-for-byte stable contract.
//
// # FROZEN — read this before touching anything in this package
//
// Wire shapes evolve like protobuf or the Kubernetes API: additive only.
// No field rename, no field removal, no semantics change, no field-number
// reuse (we don't have numbers; the analog is the JSON field name). A
// wire-shape change that cannot be expressed as an optional new field with
// a safe zero-value default requires a NEW package (v2/) — never an
// in-place edit of v1.
//
// See agentpolicy/docs/DECISION_RPC.md for the full reference (semantics,
// examples, evolution rules, citations to Protobuf + Kubernetes API
// versioning discipline).
//
// # What lives here vs. what lives in internal/policy
//
// This package is the BOUNDARY contract — the bytes on the socket between
// a Policy Enforcement Point (PEP — PATH shim, runtime hook, mitmproxy
// addon) and the daemon. It is intentionally minimal and stable.
//
// agentpolicy/internal/policy.Input + .Decision are the INTERNAL engine
// types. They carry far more fields (Cerbos-shape Principal/Resource/
// Action, flat legacy fields like Program/Host/Path, evaluator context)
// because the engine needs them; PEPs do not. Internal types may evolve
// freely behind this contract.
//
// # Module placement
//
// This package sits inside agentpolicy/ so the wire contract ships with
// the engine that defines it. Consumers (daemon, runtime hook bridge,
// future polyglot clients) import it via the agentpolicy module path.
// It deliberately has zero dependencies on internal/policy or
// internal/perm so it can be vendored standalone.
package v1

// Request is the JSON object a PEP writes (one per newline-delimited
// frame) on the daemon socket. Carrying a non-empty ReqID asks the daemon
// to write back exactly one Response on the same connection.
//
// A Request with an empty ReqID is the historical fire-and-forget audit
// frame: no Response is written. PEPs that need a verdict before
// proceeding MUST set ReqID to a value unique within the lifetime of the
// connection (a counter or UUID is fine).
//
// JSON field names + types are frozen. New optional fields may be added
// in future patch releases of this package iff they are safe-by-default
// for older daemons that ignore them. They MUST NOT change the meaning of
// existing fields.
type Request struct {
	// Hook is the capture surface the frame originated from. One of:
	// "exec" (process spawn), "http" (outbound HTTP), "file" (filesystem
	// op), "ping" (liveness probe). Required for non-ping frames.
	Hook string `json:"hook"`

	// Op is a hook-specific verb. Examples: for hook="http" -> "GET" /
	// "POST"; for hook="exec" -> unset (the program path lives in attrs).
	Op string `json:"op,omitempty"`

	// PID is the OS process ID of the agent process that emitted the
	// frame. Used by the engine to bind decisions to a session.
	PID int `json:"pid,omitempty"`

	// PPID is the parent process ID. Combined with PID this lets the
	// engine validate the caller against the wrapped-agent process tree.
	PPID int `json:"ppid,omitempty"`

	// Track names which capture surface emitted the frame. One of
	// "node" (runtime hook), "native" (PATH shim), "vm" (mitmproxy
	// addon). Surfaces for which the field is irrelevant leave it empty.
	Track string `json:"track,omitempty"`

	// Attributes is the hook-specific payload: argv, host+port, path,
	// method, headers, etc. The engine projects it into its internal
	// Input shape. Keys + value types per hook are documented in
	// agentpolicy/docs/DECISION_RPC.md; new keys are additive.
	Attributes map[string]any `json:"attrs,omitempty"`

	// ReqID, when non-empty, switches this frame into sync-RPC mode:
	// the daemon writes back exactly one Response that echoes the same
	// ReqID. Empty ReqID = fire-and-forget audit frame, no response.
	ReqID string `json:"req_id,omitempty"`
}

// Response is the JSON object the daemon writes back on the same
// connection in reply to a Request whose ReqID was non-empty. Exactly
// one Response per such Request, on its own newline-terminated line.
//
// The four fields below are the FROZEN v1 shape from commit 264eadd.
// They are sufficient for every PEP to decide whether to proceed,
// abort, or escalate. Any future op-specific payload (e.g. credentials
// for a cred.fetch) MUST be expressed as a new versioned message under
// a new package — never tacked onto Response as a free-form bag.
type Response struct {
	// ReqID echoes the Request.ReqID byte-for-byte so a client may
	// multiplex requests on one connection.
	ReqID string `json:"req_id"`

	// Action is the verdict. See type Action below for the closed enum.
	Action Action `json:"action"`

	// RuleID identifies the policy rule that produced the verdict.
	// Empty when the verdict is the no-rule default ("allow") or comes
	// from a non-rule path (engine disabled, eval error, ping).
	RuleID string `json:"rule_id,omitempty"`

	// Reason is a short machine-readable string that explains the
	// verdict when no RuleID applies. Documented values:
	//   "ping"             — ping liveness probe answered allow
	//   "policy disabled"  — daemon has no engine loaded; allow by default
	//   "eval_error"       — engine returned an error; fail-open allow
	//   "no_rule"          — no rule matched; allow is the default
	// Empty Reason on a deny/ask response means RuleID carries the
	// authoritative explanation.
	Reason string `json:"reason,omitempty"`
}

// Action is the verdict enum. Encoded as a JSON string. The closed set
// of values is part of the v1 contract: adding a new verdict requires a
// new versioned package.
type Action string

const (
	// ActionAllow — the PEP MAY proceed.
	ActionAllow Action = "allow"

	// ActionDeny — the PEP MUST abort the operation.
	ActionDeny Action = "deny"

	// ActionAsk — the operation requires out-of-band human approval.
	// The PEP MUST NOT proceed until a follow-up signal arrives via a
	// separate channel (today: the approval CLI; future: the
	// agentpermissions approval flow). Treat as deny if the PEP cannot
	// suspend the operation.
	ActionAsk Action = "ask"
)
