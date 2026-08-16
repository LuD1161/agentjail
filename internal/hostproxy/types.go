// Package hostproxy owns the bounded host-command proxy contract.
package hostproxy

import "time"

type Action string

const (
	ActionAsk  Action = "ask"
	ActionDeny Action = "deny"
)

type SessionID string
type Proof string

type Target struct {
	Executable string   `json:"executable"`
	Argv       []string `json:"argv"`
}

type Request struct {
	Proof  Proof  `json:"proof"`
	Target Target `json:"target"`
	CWD    string `json:"cwd"`
}

type Result struct {
	Stdout    []byte        `json:"stdout,omitempty"`
	Stderr    []byte        `json:"stderr,omitempty"`
	ExitCode  int           `json:"exit_code"`
	TimedOut  bool          `json:"timed_out,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	Duration  time.Duration `json:"duration_ns,omitempty"`
}

const (
	RequestType           = "host_proxy_exec"
	DefaultTimeout        = 30 * time.Second
	DefaultOutputLimit    = 1024 * 1024
	MaxRequestBytes       = 128 * 1024
	MaxResponseBytes      = 2 * 1024 * 1024
	ProofEnvironmentName  = "AGENTJAIL_HOST_PROXY_PROOF"
	TargetEnvironmentName = "AGENTJAIL_HOST_PROXY_EXECUTABLE"
)

type WireRequest struct {
	Type    string  `json:"type"`
	Request Request `json:"request"`
}

type WireResponse struct {
	OK     bool   `json:"ok"`
	Result Result `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}
