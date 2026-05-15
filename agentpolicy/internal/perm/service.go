package perm

import (
	"context"
	"fmt"
	"os"

	"github.com/LuD1161/agentjail/agentpolicy/policy"
)

// LegacyDecisionQuery is the prepared-query rule that is the SOLE source
// of truth for verdicts in Phase 1. It corresponds to the production
// policies/default.rego — UNCHANGED in this phase per the rollout plan.
const LegacyDecisionQuery = "data.agentjail.default.decision"

// ExperimentalDecisionQuery is the parallel Cerbos-shape rule package
// that the side-by-side evaluator runs against when
// AGENTJAIL_SHAPE_DISAGREEMENT=log. Verdicts from this query are
// observed but NEVER returned to the caller — promotion is manual
// (move the file + re-run smoke fixtures).
const ExperimentalDecisionQuery = "data.agentjail.experimental.decision"

// DisagreementEvent is the audit-log row emitted when the legacy and
// experimental shapes disagree on a verdict. Surfaced to the daemon's
// telemetry exporter via the Emitter interface so this package stays
// telemetry-agnostic.
type DisagreementEvent struct {
	RequestID  string
	Principal  string // principal.id
	Action     Action
	Resource   string // resource.kind + ":" + resource.id
	LegacyAct  string
	LegacyRule string
	ExpAct     string
	ExpRule    string
}

// Emitter is the minimum surface perm.Service needs to drop an audit
// event. Satisfied by internal/telemetry.Exporter without an import
// (avoids a cycle if telemetry ever wants to read perm types).
type Emitter interface {
	Emit(body string, attrs map[string]any) error
}

// Service is the façade in front of policy.Engine that consumes the
// Cerbos-shape CheckResourcesRequest. Today it delegates to the legacy
// OPA query for the verdict and, when configured, runs the experimental
// query side-by-side to surface disagreements.
type Service struct {
	engine  *policy.Engine
	emitter Emitter
}

// NewService constructs a Service around an existing policy.Engine. The
// emitter is optional — when nil, disagreement events are dropped on the
// floor (still useful in tests where we assert on the comparison via
// CheckResourcesPair below).
func NewService(eng *policy.Engine, emit Emitter) *Service {
	return &Service{engine: eng, emitter: emit}
}

// CheckResources is the public entry point. The verdict is ALWAYS the
// legacy one in Phase 1 (codex blocker — new-shape rules must not
// affect prod). When AGENTJAIL_SHAPE_DISAGREEMENT=log is set, the
// experimental query runs in parallel and a policy.shape_disagreement
// event is emitted when the two disagree.
func (s *Service) CheckResources(ctx context.Context, req CheckResourcesRequest) (CheckResourcesResponse, error) {
	if s == nil || s.engine == nil {
		return CheckResourcesResponse{RequestID: req.RequestID, Effect: "allow"}, nil
	}
	legacy, err := s.engine.Eval(ctx, BuildPolicyInput(req))
	if err != nil {
		// Fail-open at this layer — matches existing daemon behavior.
		return CheckResourcesResponse{
			RequestID: req.RequestID,
			Effect:    "allow",
		}, err
	}
	resp := CheckResourcesResponse{
		RequestID: req.RequestID,
		Effect:    legacy.Action,
		RuleID:    legacy.RuleID,
	}
	if disagreementMode() {
		s.observeExperimental(ctx, req, legacy)
	}
	return resp, nil
}

// observeExperimental runs the alternate query and emits a disagreement
// event if the two decisions don't match. Always returns nil — this is
// observability, not a control-plane decision.
func (s *Service) observeExperimental(ctx context.Context, req CheckResourcesRequest, legacy policy.Decision) {
	exp, err := s.engine.EvalQuery(ctx, ExperimentalDecisionQuery, BuildPolicyInput(req))
	if err != nil {
		// Missing experimental package or a malformed exp rule shouldn't
		// crash the prod path; just skip the comparison this round.
		return
	}
	if exp.Action == legacy.Action && exp.RuleID == legacy.RuleID {
		return
	}
	if s.emitter == nil {
		return
	}
	resID := req.Resource.Kind + ":" + req.Resource.ID
	_ = s.emitter.Emit("policy.shape_disagreement", map[string]any{
		"request_id":           req.RequestID,
		"principal.id":         req.Principal.ID,
		"action":               string(req.Action),
		"resource":             resID,
		"legacy.action":        legacy.Action,
		"legacy.rule_id":       legacy.RuleID,
		"experimental.action":  exp.Action,
		"experimental.rule_id": exp.RuleID,
	})
}

// ObserveExperimental is the exported entry point the daemon uses when it
// has already computed the legacy verdict via engine.Eval against a
// richer Input (one that carries the legacy Flags/Positional/
// PathsResolved fields normalize() builds). Avoids paying for a second
// legacy query — we just need to know whether the experimental query
// would disagree.
//
// Always returns nil for the same reason as the internal helper: the
// side-by-side path is observability only.
func (s *Service) ObserveExperimental(ctx context.Context, req CheckResourcesRequest, legacyAct, legacyRule string) {
	if s == nil || s.engine == nil || !disagreementMode() {
		return
	}
	s.observeExperimental(ctx, req, policy.Decision{Action: legacyAct, RuleID: legacyRule})
}

// BuildPolicyInput projects a CheckResourcesRequest into the
// policy.Input shape that the OPA engine wants. The new Cerbos-shape
// fields go top-level (input.principal, input.resource, input.action)
// AND nested under input.req (the full request), per the Phase 1 plan.
// The legacy flat fields (input.program, input.path, ...) are populated
// from the resource attrs so existing rules continue to fire.
func BuildPolicyInput(req CheckResourcesRequest) policy.Input {
	in := policy.Input{
		Action:    string(req.Action),
		Principal: principalToMap(req.Principal),
		Resource:  resourceToMap(req.Resource),
		Context: map[string]any{
			"home":     req.Context.Home,
			"cwd_repo": req.Context.CwdRepo,
		},
		Req: requestToMap(req),
	}
	// Legacy flat fields so existing default.rego rules still match.
	switch req.Resource.Kind {
	case "subprocess":
		in.Hook = "exec"
		if p, ok := req.Resource.Attr["program"].(string); ok {
			in.Program = p
		}
		if pp, ok := req.Resource.Attr["program_path"].(string); ok {
			in.ProgramPath = pp
		}
		if argv, ok := req.Resource.Attr["argv_raw"].([]string); ok {
			in.ArgvRaw = argv
		} else if argvAny, ok := req.Resource.Attr["argv_raw"].([]any); ok {
			for _, a := range argvAny {
				if s, ok := a.(string); ok {
					in.ArgvRaw = append(in.ArgvRaw, s)
				}
			}
		}
		if cwd, ok := req.Resource.Attr["cwd"].(string); ok {
			in.Cwd = cwd
		}
	case "file":
		in.Hook = "file"
		if p, ok := req.Resource.Attr["path"].(string); ok {
			in.Path = p
		}
		if op, ok := req.Resource.Attr["op"].(string); ok {
			in.Op = op
		}
	case "http_request":
		in.Hook = "http"
		if h, ok := req.Resource.Attr["host"].(string); ok {
			in.Host = h
		}
		if m, ok := req.Resource.Attr["method"].(string); ok {
			in.Method = m
		}
		if pa, ok := req.Resource.Attr["path"].(string); ok {
			in.Path = pa
		}
		switch v := req.Resource.Attr["port"].(type) {
		case float64:
			in.Port = int(v)
		case int:
			in.Port = v
		}
	}
	return in
}

// PrincipalToMap projects a Principal into the map shape OPA Rego rules
// match on (input.principal.{id, roles, attr}). Exported so daemon code
// can populate the legacy Input.Principal field without re-defining the
// canonicalization.
func PrincipalToMap(p Principal) map[string]any {
	if p.ID == "" && len(p.Attr) == 0 {
		return nil
	}
	m := map[string]any{
		"id":   p.ID,
		"attr": p.Attr,
	}
	if len(p.Roles) > 0 {
		m["roles"] = p.Roles
	}
	return m
}

// ResourceToMap projects a Resource into the map shape OPA Rego rules
// match on (input.resource.{id, kind, attr}).
func ResourceToMap(r Resource) map[string]any {
	if r.Kind == "" && r.ID == "" && len(r.Attr) == 0 {
		return nil
	}
	return map[string]any{
		"id":   r.ID,
		"kind": r.Kind,
		"attr": r.Attr,
	}
}

func principalToMap(p Principal) map[string]any { return PrincipalToMap(p) }
func resourceToMap(r Resource) map[string]any   { return ResourceToMap(r) }

func requestToMap(req CheckResourcesRequest) map[string]any {
	return map[string]any{
		"request_id": req.RequestID,
		"principal":  principalToMap(req.Principal),
		"resource":   resourceToMap(req.Resource),
		"action":     string(req.Action),
		"context": map[string]any{
			"home":     req.Context.Home,
			"cwd_repo": req.Context.CwdRepo,
		},
	}
}

// disagreementMode reports whether AGENTJAIL_SHAPE_DISAGREEMENT=log is
// active. Anything other than "log" disables comparison, which keeps the
// flag forward-compatible for future modes (e.g. "deny-on-disagreement").
func disagreementMode() bool {
	return os.Getenv("AGENTJAIL_SHAPE_DISAGREEMENT") == "log"
}

// String for Action: handy for log lines without an extra cast.
func (a Action) String() string { return string(a) }

// debug helper for the test suite; not part of the public API.
func formatDisagreement(d DisagreementEvent) string {
	return fmt.Sprintf("disagree(principal=%s action=%s resource=%s legacy=%s/%s exp=%s/%s)",
		d.Principal, d.Action, d.Resource, d.LegacyAct, d.LegacyRule, d.ExpAct, d.ExpRule)
}
