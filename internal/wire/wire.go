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
