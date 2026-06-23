// Package policy defines the Engine interface and its OPA in-process
// implementation for evaluating hook-wire-format inputs against Rego policies.
//
// Architecture note: this file adds two things on top of the legacy
// policy.go engine:
//
//  1. HookInput — a flat, hook-wire-format struct matching the Claude Code
//     PreToolUse payload. Legacy callers use policy.Input; new hook-path
//     callers use HookInput.
//
//  2. Engine interface — allows tests and future implementations (WASM,
//     remote, no-op) to swap out the OPA backend without changing callers.
//     The concrete type is hookOPAEngine below; NewHookOPAEngine returns it.
//
// Query path: data.agentjail.decision (distinct from the legacy
// data.agentjail.default.decision used by policy.go). New Rego rules
// targeting the hook path belong in package agentjail under the rule name
// "decision".
//
// Default-deny semantics: if no rule fires (empty result set), the engine
// returns Decision{Action:"ask", Reason:"no policy matched — defaulting to ask"}.
// This matches the "fail safe" principle: an unknown situation escalates to
// a human rather than silently allowing.
package policy

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// HookInput is the canonical input record for the Claude Code hook wire
// format (PreToolUse / PostToolUse events). It is intentionally separate
// from the legacy Input type so the two shapes can evolve independently.
//
// Rego rules receive this as the OPA `input` document; field names match
// the JSON tags exactly (snake_case, no omitempty so absence is visible).
type HookInput struct {
	HookEvent string                 `json:"hook_event"` // "PreToolUse", "PostToolUse"
	ToolName  string                 `json:"tool_name"`  // "Bash", "Write", "Edit", "Read", "mcp__server__tool"
	ToolInput map[string]interface{} `json:"tool_input"` // raw tool_input from the hook
	SessionID string                 `json:"session_id"`
	CWD       string                 `json:"cwd"`
	RepoRoot  string                 `json:"repo_root,omitempty"` // git repo root resolved by daemon; empty if not a git repo
	// AWSAccount is the AWS account id targeted by an `aws --profile <name>`
	// CLI command, resolved by the daemon from ~/.aws/config before Rego eval
	// (empty for non-AWS commands or when unresolvable). Rego reads it as
	// input.aws_account to apply per-account posture (aws_policy/*). Omitted
	// from the JSON when empty so Rego sees it as undefined for non-AWS calls.
	AWSAccount string `json:"aws_account,omitempty"`
	// CommandBinaries is the list of command binary basenames extracted from
	// a Bash tool_input.command by the daemon's shell parser. For example,
	// "git status && /usr/local/bin/agentjail policy list | grep foo" yields
	// ["git", "agentjail", "grep"]. Empty for non-Bash tools.
	// Rego reads this as input.command_binaries.
	CommandBinaries []string `json:"command_binaries,omitempty"`
}

// Engine is the abstraction new callers depend on. The concrete
// implementation (hookOPAEngine) evaluates OPA Rego in-process; future
// implementations (WASM bundle, no-op for tests, remote stub) satisfy the
// same interface.
//
// Eval must be safe for concurrent use from multiple goroutines.
type Engine interface {
	Eval(ctx context.Context, input HookInput) (Decision, error)
}

// hookOPAEngine is the in-process OPA implementation of Engine.
// It compiles Rego at construction time (PreparedEvalQuery) and re-uses the
// warm query for every Eval call — cold-start cost is paid once.
//
// Thread-safety: qMu guards the prepared query so hot-reload (if wired
// later) can swap it atomically while Eval is running on other goroutines.
type hookOPAEngine struct {
	qMu sync.RWMutex
	q   rego.PreparedEvalQuery
}

// hookDecisionQuery is the OPA rule path for hook-wire-format decisions.
// Distinct from the legacy data.agentjail.default.decision so the two rule
// sets can evolve independently and be composed separately.
const hookDecisionQuery = "data.agentjail.decision"

// hookDefaultDecision is returned when no rule fires (empty result set).
// "ask" rather than "allow" or "deny" — unknown situations escalate to a
// human; they are not silently permitted.
var hookDefaultDecision = Decision{
	Action: "ask",
	Reason: "no policy matched — defaulting to ask",
}

// NewHookOPAEngine compiles the given Rego modules into a PreparedEvalQuery
// and returns a ready-to-use Engine. Each element of modules is a
// (filename, rego-source) pair.
//
// Returns an error if the Rego fails to compile (syntax error, undefined
// reference, etc.). A zero-length modules slice is valid — it produces an
// engine that always returns the default-ask decision.
//
// For data injection (e.g. data.agentjail.config), use
// NewHookOPAEngineWithData instead.
func NewHookOPAEngine(ctx context.Context, modules [][2]string) (Engine, error) {
	return NewHookOPAEngineWithData(ctx, modules, nil)
}

// NewHookOPAEngineWithData compiles the given Rego modules and wires the
// provided data document into the OPA store so policies can read it via the
// data.agentjail namespace (e.g. data.agentjail.config.mcp.allowed).
//
// agentjailData must be a JSON-compatible map[string]interface{} that
// represents the content under the "agentjail" key in the OPA data document.
// The daemon wraps cfg.ToOPAData() under {"config": ...} before passing it:
//
//	agentjailData = map[string]interface{}{"config": cfg.ToOPAData()}
//
// The full OPA data document then becomes:
//
//	{ "agentjail": { "config": { "mcp": {...}, "file": {...}, ... } } }
//
// so Rego reads e.g. data.agentjail.config.mcp.allowed.
//
// Pass agentjailData=nil to omit data injection (equivalent to NewHookOPAEngine).
// The engine is rebuilt on every SIGHUP with the updated data document.
func NewHookOPAEngineWithData(ctx context.Context, modules [][2]string, agentjailData map[string]interface{}) (Engine, error) {
	opts := make([]func(*rego.Rego), 0, len(modules)+2)
	for _, m := range modules {
		opts = append(opts, rego.Module(m[0], m[1]))
	}
	opts = append(opts, rego.Query(hookDecisionQuery))
	if agentjailData != nil {
		// Wrap under {"agentjail": ...} so policies read data.agentjail.<key>.
		storeData := map[string]interface{}{
			"agentjail": agentjailData,
		}
		opts = append(opts, rego.Store(newInMemoryStore(storeData)))
	}
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile hook rego modules: %w", err)
	}
	return &hookOPAEngine{q: q}, nil
}

// newInMemoryStore creates an OPA in-memory storage.Store pre-loaded with
// the given data document.  inmem.NewFromObject never returns an error for a
// valid map argument.
func newInMemoryStore(data map[string]interface{}) storage.Store {
	return inmem.NewFromObject(data)
}

// Eval evaluates the hook input against the compiled Rego policy and returns
// a Decision. It is safe for concurrent use.
//
// If the OPA query returns an error, Eval returns that error alongside a
// zero-value Decision — callers must treat an error as a signal to fail-safe
// (typically returning "ask" or "deny" depending on the enforcement context).
//
// If the query succeeds but no rule fires (empty result set or a nil value),
// Eval returns hookDefaultDecision (action="ask") with a nil error.
func (e *hookOPAEngine) Eval(ctx context.Context, input HookInput) (Decision, error) {
	e.qMu.RLock()
	q := e.q
	e.qMu.RUnlock()

	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("opa eval: %w", err)
	}
	return hookDecisionFromResultSet(rs), nil
}

// hookDecisionFromResultSet extracts a Decision from an OPA result set.
// Expected shape: {"action": "allow"|"deny"|"ask", "reason": "...", "rule_id": "...", "impact": "..."}
// Any missing field is left as a zero-value string.
func hookDecisionFromResultSet(rs rego.ResultSet) Decision {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return hookDefaultDecision
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok || m == nil {
		return hookDefaultDecision
	}
	d := Decision{}
	if a, _ := m["action"].(string); a != "" {
		d.Action = a
	} else {
		// action field present but empty → treat as default
		return hookDefaultDecision
	}
	d.Reason, _ = m["reason"].(string)
	d.RuleID, _ = m["rule_id"].(string)
	d.Impact, _ = m["impact"].(string)
	return d
}
