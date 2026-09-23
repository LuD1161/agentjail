package netpolicy

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCompiledMatcherPreservesSelectionAndRendering(t *testing.T) {
	dir := writeTestTemplate(t, "rules.yaml", `
id: first
info: {severity: high}
match: {path: ["re:[", "re:^/Case$"]}
action: deny
reason: "{{.Verb}} {{range .ScanHits}}{{.RuleName}}{{end}}"
impact: "{{.Missing}}"
scan:
  payload: [{type: contains, patterns: [marker], name: hit}]
---
id: tied
info: {severity: high}
match: {path: ["/case"]}
action: deny
reason: second
---
id: lower
info: {severity: critical}
action: ask
reason: lower
`)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	op := &Operation{Path: "/Case", Verb: "create", Payload: map[string]any{"text": "marker"}}
	check := func() {
		t.Helper()
		result := m.Evaluate(op)
		if result == nil || result.Template.ID != "first" || result.Reason != "create hit" || result.Impact != "{{.Missing}}" || len(result.ScanHits) != 1 {
			t.Errorf("unexpected selection/rendering: %#v", result)
		}
	}
	check()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				check()
			}
		}()
	}
	wg.Wait()
	op.Path = "/case"
	if got := m.Evaluate(op); got == nil || got.Template.ID != "tied" {
		t.Fatalf("regex case semantics changed: %#v", got)
	}
	op.Path = "/Case"
	op.Payload["text"] = "other"
	if got := m.Evaluate(op); got == nil || got.Template.ID != "tied" {
		t.Fatalf("scan miss semantics changed: %#v", got)
	}
}

func TestCompiledMatcherPreservesInvalidReason(t *testing.T) {
	dir := writeTestTemplate(t, "rule.yaml", `
id: invalid-reason
action: allow
reason: "{{"
`)
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Evaluate(&Operation{}); got == nil || got.Reason != "{{" {
		t.Fatalf("invalid reason fallback changed: %#v", got)
	}
}

type countedPayload struct {
	calls *atomic.Int64
	value string
}

func (p countedPayload) MarshalJSON() ([]byte, error) { p.calls.Add(1); return json.Marshal(p.value) }

func TestMatcherSerializesPayloadOncePerOperation(t *testing.T) {
	rule := `
id: RULE
action: deny
scan:
  payload: [{type: contains, patterns: [marker], name: marker}]
`
	dir := writeTestTemplate(t, "rules.yaml", strings.ReplaceAll(rule, "RULE", "first")+"---\n"+strings.ReplaceAll(rule, "RULE", "second"))
	m, err := NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	op := &Operation{Payload: map[string]any{"text": countedPayload{&calls, "marker"}}}
	if result := m.Evaluate(op); result == nil {
		t.Fatal("missing match")
	}
	if calls.Load() != 1 {
		t.Fatalf("serialization count = %d, want 1", calls.Load())
	}
	op.Payload["text"] = countedPayload{&calls, "other"}
	if result := m.Evaluate(op); result != nil {
		t.Fatalf("stale payload match: %#v", result)
	}
	if calls.Load() != 2 {
		t.Fatalf("serialization count = %d, want 2", calls.Load())
	}
}
