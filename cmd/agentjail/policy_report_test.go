package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/store"
)

type fakePolicyReportStore struct {
	totals   []store.PolicyMatchCount
	sessions []store.PolicySessionMatch
}

func (f fakePolicyReportStore) CountPolicyMatches(context.Context) ([]store.PolicyMatchCount, error) {
	return f.totals, nil
}

func (f fakePolicyReportStore) CountPolicyMatchesBySession(context.Context, int) ([]store.PolicySessionMatch, error) {
	return f.sessions, nil
}

func TestCollectPolicyReportUsesActiveSourceAndBoundedSessionPath(t *testing.T) {
	home := t.TempDir()
	rulesDir := filepath.Join(home, ".agentjail", "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	source := `package agentjail

candidate contains r if {
    r := {
        "action": "deny",
        "reason": "agents must not escalate privileges via sudo",
        "rule_id": "command_policy/no-sudo",
        "impact": "would escalate to root",
    }
}

candidate contains r if {
    r := {"action": "allow", "rule_id": "command_policy/default-allow"}
}
`
	if err := os.WriteFile(filepath.Join(rulesDir, "command_policy.rego"), []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".agentjail", "policy.yaml"), []byte("disabled_rules:\n  - command_policy/default-allow\n"), 0o600); err != nil {
		t.Fatalf("WriteFile policy: %v", err)
	}

	history := fakePolicyReportStore{
		totals: []store.PolicyMatchCount{{RuleID: "command_policy/no-sudo", Count: 7, AgentCount: 1, SessionCount: 1}},
		sessions: []store.PolicySessionMatch{{
			RuleID: "command_policy/no-sudo", Agent: "codex", SessionID: "session-123", CWD: "/Users/private/Repos/secret-project", Count: 7,
		}},
	}
	report, err := collectPolicyReport(context.Background(), home, history)
	if err != nil {
		t.Fatalf("collectPolicyReport: %v", err)
	}
	if !report.HistoryAvailable || len(report.Policies) != 1 {
		t.Fatalf("report = %+v", report)
	}
	policy := report.Policies[0]
	if policy.ID != "command_policy/no-sudo" || policy.MatchedCount != 7 || policy.Source != RuleSourceCore {
		t.Fatalf("policy = %+v", policy)
	}
	if len(report.Sources) != 1 || report.Sources[0].Rego != source {
		t.Fatal("report did not preserve the exact active Rego source once")
	}
	if len(policy.Examples) != 1 || policy.Examples[0].Impact != "would escalate to root" {
		t.Fatalf("examples = %+v", policy.Examples)
	}
	if len(policy.Evaluations) != 1 || policy.Evaluations[0].SessionFolder != "…/secret-project" {
		t.Fatalf("evaluations = %+v", policy.Evaluations)
	}
	if strings.Contains(policy.Evaluations[0].SessionFolder, "/Users/") {
		t.Fatalf("session folder leaked full path: %q", policy.Evaluations[0].SessionFolder)
	}
}

func TestCollectPolicyReportMarksUnavailableHistory(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	report, err := collectPolicyReport(context.Background(), home, nil)
	if err != nil {
		t.Fatalf("collectPolicyReport: %v", err)
	}
	if report.HistoryAvailable {
		t.Fatal("missing store reported history as available")
	}
}

func TestPolicyDisplayName(t *testing.T) {
	if got := policyDisplayName("file_policy/sensitive_in_project"); got != "Sensitive In Project" {
		t.Fatalf("policyDisplayName = %q", got)
	}
}
