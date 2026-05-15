package perm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/policy"
)

// stubEmitter captures emitted disagreement events for assertion.
type stubEmitter struct {
	rows []row
}

type row struct {
	body  string
	attrs map[string]any
}

func (s *stubEmitter) Emit(body string, attrs map[string]any) error {
	s.rows = append(s.rows, row{body: body, attrs: attrs})
	return nil
}

// engineWithRules writes both a default and an experimental rule set into
// a temp policy dir and returns a compiled Engine.
func engineWithRules(t *testing.T, defaultRego, expRego string) *policy.Engine {
	t.Helper()
	tmp := t.TempDir()
	policyDir := filepath.Join(tmp, "policies")
	expDir := filepath.Join(policyDir, "experimental")
	if err := os.MkdirAll(expDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "default.rego"), []byte(defaultRego), 0o600); err != nil {
		t.Fatalf("write default: %v", err)
	}
	if err := os.WriteFile(filepath.Join(expDir, "exp.rego"), []byte(expRego), 0o600); err != nil {
		t.Fatalf("write exp: %v", err)
	}
	eng, err := policy.NewEngine(context.Background(), policyDir)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

// TestCheckResourcesReturnsLegacyVerdict pins the Phase 1 contract: even
// when the experimental shape disagrees, the caller sees the legacy
// verdict. This is the "new-shape rules must NOT affect prod" guarantee.
func TestCheckResourcesReturnsLegacyVerdict(t *testing.T) {
	const def = `package agentjail.default
default decision := {"action": "allow"}
`
	const exp = `package agentjail.experimental
import future.keywords.if
default decision := {"action": "allow"}
decision := {"action": "deny", "rule_id": "exp-deny-everything"} if true
`
	eng := engineWithRules(t, def, exp)
	emit := &stubEmitter{}
	svc := NewService(eng, emit)

	req := FromFrame(FrameInput{Hook: "exec", Op: "spawn", Attrs: map[string]any{
		"argv": []any{"ls"},
	}}, &SessionRef{ID: "s", AgentSlug: "comp-intel"}, PrincipalCtx{Home: "/h"})

	t.Setenv("AGENTJAIL_SHAPE_DISAGREEMENT", "log")
	resp, err := svc.CheckResources(context.Background(), req)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if resp.Effect != "allow" {
		t.Errorf("expected legacy ALLOW even though experimental denies, got %q", resp.Effect)
	}
	// And a disagreement event must have been emitted.
	if len(emit.rows) != 1 || emit.rows[0].body != "policy.shape_disagreement" {
		t.Fatalf("expected exactly one policy.shape_disagreement row, got %d: %+v", len(emit.rows), emit.rows)
	}
	attrs := emit.rows[0].attrs
	if attrs["legacy.action"] != "allow" || attrs["experimental.action"] != "deny" {
		t.Errorf("attrs don't reflect the divergence: %+v", attrs)
	}
}

// TestCheckResourcesNoDisagreementSilent pins that when both shapes
// agree, no event fires (even with the env on).
func TestCheckResourcesNoDisagreementSilent(t *testing.T) {
	const def = `package agentjail.default
default decision := {"action": "allow"}
`
	const exp = `package agentjail.experimental
default decision := {"action": "allow"}
`
	eng := engineWithRules(t, def, exp)
	emit := &stubEmitter{}
	svc := NewService(eng, emit)
	t.Setenv("AGENTJAIL_SHAPE_DISAGREEMENT", "log")

	req := FromFrame(FrameInput{Hook: "exec", Op: "spawn", Attrs: map[string]any{"argv": []any{"ls"}}},
		&SessionRef{ID: "s", AgentSlug: "comp-intel"}, PrincipalCtx{})
	if _, err := svc.CheckResources(context.Background(), req); err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(emit.rows) != 0 {
		t.Errorf("expected zero disagreement rows, got %d: %+v", len(emit.rows), emit.rows)
	}
}

// TestCheckResourcesDisagreementOffByDefault pins that without the env,
// the experimental query is not run at all (no telemetry leak).
func TestCheckResourcesDisagreementOffByDefault(t *testing.T) {
	const def = `package agentjail.default
default decision := {"action": "allow"}
`
	const exp = `package agentjail.experimental
import future.keywords.if
default decision := {"action": "allow"}
decision := {"action": "deny", "rule_id": "exp-deny"} if true
`
	eng := engineWithRules(t, def, exp)
	emit := &stubEmitter{}
	svc := NewService(eng, emit)
	// Explicitly clear the env (Setenv resets at test end).
	t.Setenv("AGENTJAIL_SHAPE_DISAGREEMENT", "")

	req := FromFrame(FrameInput{Hook: "file", Op: "writeFile", Attrs: map[string]any{"path": "/x"}},
		&SessionRef{ID: "s"}, PrincipalCtx{})
	resp, err := svc.CheckResources(context.Background(), req)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if resp.Effect != "allow" {
		t.Errorf("legacy verdict: %q", resp.Effect)
	}
	if len(emit.rows) != 0 {
		t.Errorf("env disabled — expected no disagreement rows, got %+v", emit.rows)
	}
}

// TestBuildPolicyInputPopulatesLegacyFields proves the projection that
// keeps the EXISTING default.rego rules firing against the new shape.
func TestBuildPolicyInputPopulatesLegacyFields(t *testing.T) {
	req := CheckResourcesRequest{
		Action: ActionExec,
		Resource: Resource{
			Kind: "subprocess",
			ID:   "subprocess:rm:abc",
			Attr: map[string]any{
				"program":      "rm",
				"program_path": "/usr/bin/rm",
				"argv_raw":     []any{"rm", "-rf", "/tmp"},
				"cwd":          "/tmp",
			},
		},
	}
	in := BuildPolicyInput(req)
	if in.Hook != "exec" {
		t.Errorf("hook: %q", in.Hook)
	}
	if in.Program != "rm" {
		t.Errorf("program: %q", in.Program)
	}
	if in.ProgramPath != "/usr/bin/rm" {
		t.Errorf("program_path: %q", in.ProgramPath)
	}
	if len(in.ArgvRaw) != 3 || in.ArgvRaw[0] != "rm" {
		t.Errorf("argv_raw: %v", in.ArgvRaw)
	}
	if in.Cwd != "/tmp" {
		t.Errorf("cwd: %q", in.Cwd)
	}
	if in.Action != "exec" {
		t.Errorf("action: %q", in.Action)
	}
	if in.Resource == nil || in.Principal != nil {
		// Principal is unpopulated in this minimal request; that's fine.
	}
	if in.Req == nil {
		t.Errorf("req should mirror the full request shape")
	}
}

// TestServiceNilGuardsReturnAllow proves the cold-start fail-open path —
// a wrapper that hasn't loaded a policy yet still gets a verdict back.
func TestServiceNilGuardsReturnAllow(t *testing.T) {
	var svc *Service
	resp, err := svc.CheckResources(context.Background(), CheckResourcesRequest{RequestID: "abc"})
	if err != nil {
		t.Fatalf("nil service: %v", err)
	}
	if resp.Effect != "allow" || resp.RequestID != "abc" {
		t.Errorf("nil service must echo request id and ALLOW: %+v", resp)
	}
}
