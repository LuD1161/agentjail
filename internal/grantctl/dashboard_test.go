package grantctl

import "testing"

func TestValidateDashboardSnapshotRejectsMalformedAndOversizedData(t *testing.T) {
	valid := DashboardSnapshotV1{
		ProtocolVersion: DashboardProtocolVersion,
		RecentSessions:  []DashboardSessionV1{}, Activity: []DashboardDayV1{}, Tokens: []DashboardTokenDayV1{}, TokenAgents: []DashboardTokenAgentV1{}, MCPTools: []DashboardMCPToolsV1{}, TokenCoverage: []string{},
		TokenStatus: DashboardTokensReady,
	}
	if err := validateDashboardSnapshotV1(valid); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	compatible := valid
	compatible.MCPTools = nil
	if err := validateDashboardSnapshotV1(compatible); err != nil {
		t.Fatalf("snapshot from daemon without additive MCP tools field: %v", err)
	}
	missing := valid
	missing.Tokens = nil
	if err := validateDashboardSnapshotV1(missing); err == nil {
		t.Fatal("nil tokens accepted")
	}
	oversized := valid
	oversized.RecentSessions = make([]DashboardSessionV1, MaxDashboardSessions+1)
	if err := validateDashboardSnapshotV1(oversized); err == nil {
		t.Fatal("oversized sessions accepted")
	}
	invalid := valid
	invalid.RecentSessions = []DashboardSessionV1{{SessionID: "s", AuditedCalls: -1}}
	if err := validateDashboardSnapshotV1(invalid); err == nil {
		t.Fatal("negative calls accepted")
	}
	invalidStatus := valid
	invalidStatus.TokenStatus = DashboardTokenStatus("unknown")
	if err := validateDashboardSnapshotV1(invalidStatus); err == nil {
		t.Fatal("unknown token status accepted")
	}
	invalidTool := valid
	invalidTool.MCPTools = []DashboardMCPToolsV1{{Server: "linear", Tools: []string{""}}}
	if err := validateDashboardSnapshotV1(invalidTool); err == nil {
		t.Fatal("empty MCP tool name accepted")
	}
}
