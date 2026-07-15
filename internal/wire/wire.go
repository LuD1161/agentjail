// Package wire defines the canonical daemon RPC wire shape for agentjail.
//
// The daemon speaks a simple newline-delimited JSON protocol over a Unix
// domain socket (~/.agentjail/daemon.sock). This package consolidates the
// shared types so callers (agentjail-hook, agentjail try, and other CLI
// callers) stay in sync without copy-drift.
//
// Wire protocol (one JSON object per line, '\n' terminated):
//
//	Request:  {"id":"...","hook_event":"PreToolUse","tool_name":"Bash","tool_input":{...},"session_id":"...","cwd":"..."}
//	Response: {"id":"...","action":"allow|ask|deny","reason":"...","rule_id":"...","impact":"..."}
//
// This is the CURRENT legacy shape the daemon speaks. It is NOT the frozen
// v1 shape from agentpolicy/docs/DECISION_RPC.md (which uses req_id/hook/attrs).
package wire

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Request is the wire shape the daemon expects on its Unix socket.
// Field names must match the daemon's JSON tags exactly; snake_case, no omitempty.
type Request struct {
	ID        string                 `json:"id"`
	HookEvent string                 `json:"hook_event"`
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	SessionID string                 `json:"session_id"`
	CWD       string                 `json:"cwd"`
	Agent     string                 `json:"agent,omitempty"`
	AgentPID  int                    `json:"agent_pid,omitempty"`
}

// Response is the wire shape the daemon returns over the Unix socket.
// Impact carries "consequence-of-allowing" text forwarded from Decision.Impact;
// it is omitempty because the daemon only includes it when a rule populates it.
type Response struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
	Impact string `json:"impact,omitempty"`
}

// DefaultSocketPath returns the default path for the daemon Unix socket.
// Expands to ~/.agentjail/daemon.sock; falls back to /tmp/agentjail-daemon.sock
// if the home directory cannot be determined.
func DefaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.sock"
	}
	return filepath.Join(home, ".agentjail", "daemon.sock")
}

// FailOpenWarnedSentinelPath returns the path to the one-time fail-open
// warning sentinel (~/.agentjail/fail-open-warned), next to the default
// daemon socket. agentjail-hook creates this file the first time it fails
// open (daemon unreachable) so it only warns once per outage; the daemon
// removes it on successful startup so the warning re-arms for the next
// outage (U2). Both sides call this single function so the path can never
// drift between them.
func FailOpenWarnedSentinelPath() string {
	return filepath.Join(filepath.Dir(DefaultSocketPath()), "fail-open-warned")
}

// HookFallbackPath returns the path to the daemon-written hook-fallback
// sidecar. Expands to ~/.agentjail/hook-fallback.json; falls back to
// /tmp/agentjail-hook-fallback.json if the home directory cannot be
// determined (mirrors DefaultSocketPath's fallback convention).
//
// See ADR 0050: the daemon writes this file (atomically, temp+rename, 0600)
// on startup and every SIGHUP reload so the stdlib-only hook can learn the
// configured daemon_unreachable level and offline critical-denylist rules
// without reading policy.yaml or running OPA.
func HookFallbackPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-hook-fallback.json"
	}
	return filepath.Join(home, ".agentjail", "hook-fallback.json")
}

// HookFallbackVersion is the current version of the HookFallback JSON shape.
// The hook treats any other Version value (or an unparseable/missing file)
// as if the sidecar were absent, falling back to "allow" (see ADR 0050).
const HookFallbackVersion = 1

// HookFallback is the JSON shape the daemon writes to HookFallbackPath() and
// the hook reads when (and only when) the daemon is unreachable. Shared by
// both processes so they can never drift on field names/types.
type HookFallback struct {
	// Version must equal HookFallbackVersion. A mismatched or missing
	// version means the hook cannot trust the rest of the document and
	// falls back to "allow".
	Version int `json:"version"`

	// Level is one of "allow" | "degraded" | "deny" (mirrors
	// agentpolicy/config.DaemonUnreachableLevel as a plain string so the
	// stdlib-only hook never needs to import the config package). Any other
	// value is treated as "allow" by the hook.
	Level string `json:"level"`

	// OfflineRules is the compiled offline critical-denylist the hook
	// enforces when Level == "degraded". Populated by the daemon from the
	// locked-rule set (see agentpolicy/policies/resolver.rego's
	// locked_rules); empty for "allow"/"deny" levels.
	OfflineRules []OfflineRule `json:"offline_rules"`
}

// OfflineRuleKind names the shape of matcher an OfflineRule carries. The
// hook dispatches on Kind with a stdlib-only matcher — no Rego, no OPA.
type OfflineRuleKind string

const (
	// OfflineRuleKindPathPrefixWrite denies Write/Edit tool calls whose
	// normalized target path is under any of PathPrefixes.
	OfflineRuleKindPathPrefixWrite OfflineRuleKind = "path_prefix_write"

	// OfflineRuleKindPathRead denies Read tool calls whose normalized target
	// path equals, or is under, any of PathPrefixes.
	OfflineRuleKindPathRead OfflineRuleKind = "path_read"

	// OfflineRuleKindCommandMutation denies Bash tool calls whose parsed
	// command binaries include one of Binaries AND whose raw command string
	// matches one of Patterns (regexp, mirroring the always-on mutation
	// guard in agentpolicy/policies/command_policy.rego).
	OfflineRuleKindCommandMutation OfflineRuleKind = "command_mutation"
)

// OfflineRule is one compiled offline critical-denylist entry. The daemon is
// the sole author of OfflineRule values (it owns the locked-rule
// definitions); the hook only matches, never defines, a rule.
type OfflineRule struct {
	// Kind selects which fields below are meaningful (see OfflineRuleKind*).
	Kind OfflineRuleKind `json:"kind"`

	// RuleID is surfaced in the hook's deny reason/telemetry, e.g.
	// "file_policy/agentjail_self". Mirrors the locked rule_id it offline-
	// enforces so a denial under "degraded" reads the same as one from OPA.
	RuleID string `json:"rule_id"`

	// Reason is the human-readable deny reason.
	Reason string `json:"reason"`

	// PathPrefixes is used by OfflineRuleKindPathPrefixWrite/PathRead. Every
	// entry is an absolute, already-home-expanded path (the daemon resolves
	// ~ using its own os.UserHomeDir() before writing the sidecar, since it
	// runs as the same user as the hook).
	PathPrefixes []string `json:"path_prefixes,omitempty"`

	// Binaries is used by OfflineRuleKindCommandMutation: the parsed command
	// must contain at least one of these binaries (via internal/shellparse)
	// for Patterns to be checked at all.
	Binaries []string `json:"binaries,omitempty"`

	// Patterns is used by OfflineRuleKindCommandMutation: stdlib regexp
	// patterns checked against the raw command string. Any match fires the
	// rule (once Binaries has already matched).
	Patterns []string `json:"patterns,omitempty"`
}

// ControlType is the Request.Type discriminator for a control-plane message
// on the daemon's agent socket (daemon.sock), as opposed to a policy-eval
// request or a grant_request probe. handleConn's probe-then-dispatch pattern
// checks Type before unmarshalling the full payload, mirroring how
// grantctl.ReqGrantRequest is dispatched.
const ControlType = "control"

// ControlOpReload asks the daemon to reload policy.yaml and the Rego rule
// bundle in place -- the same operation SIGHUP triggers, but delivered over
// the socket so the caller receives an explicit ControlResponse instead of
// having to guess whether the reload (and, critically, whether it compiled)
// succeeded.
const ControlOpReload = "reload"

// ControlOpPing is a side-effect-free liveness probe: the daemon replies
// ControlResponse{OK:true} and does nothing else (no reload, no decision
// recorded). The single-instance guard uses it to tell a live agentjail daemon
// from a foreign process merely squatting on the socket, so a bare successful
// connect() is never mistaken for a healthy daemon (see
// internal/daemonapp/singleton.go).
const ControlOpPing = "ping"

// ControlRequest is the wire shape for a daemon control-plane message. Type
// must equal ControlType; Op selects the operation (ControlOpReload or
// ControlOpPing).
type ControlRequest struct {
	Type string `json:"type"`
	Op   string `json:"op"`
}

// ControlResponse is the daemon's reply to a ControlRequest. OK reports
// whether the operation succeeded; Error carries the failure reason (e.g. a
// Rego compile error) so the caller can surface it instead of silently
// assuming the reload took effect.
type ControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// EvalOne is the reusable daemon RPC client for agentjail CLI callers.
//
// It dials socketPath over a Unix domain socket using DialTimeout=timeout,
// sets a write+read deadline of timeout, JSON-encodes req (newline-terminated),
// reads exactly one response line with a 1 MB scanner buffer, and unmarshals
// the Response. Returns an error on dial failure, I/O error, or JSON error.
//
// The hook uses its own dial logic (30 ms budget, fail-open error categorisation)
// and is out of scope for this helper.
func EvalOne(socketPath string, timeout time.Duration, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return Response{}, fmt.Errorf("daemon not reachable — run `agentjail status`: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Response{}, fmt.Errorf("set deadline: %w", err)
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return Response{}, fmt.Errorf("write request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	if !scanner.Scan() {
		scanErr := scanner.Err()
		if scanErr == nil {
			scanErr = fmt.Errorf("EOF")
		}
		return Response{}, fmt.Errorf("read response: %w", scanErr)
	}

	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return Response{}, fmt.Errorf("parse response: %w", err)
	}
	return resp, nil
}
