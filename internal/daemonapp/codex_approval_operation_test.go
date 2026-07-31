package daemonapp

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/wire"
)

func TestCodexApprovalOperationForCapabilities(t *testing.T) {
	for _, tt := range []struct {
		name         string
		capabilities []string
		want         approvalexec.Operation
	}{
		{
			name:         "generic capability wins over legacy",
			capabilities: []string{wire.CapabilityCodexApprovalBridgeV1, wire.CapabilityCodexShellApprovalV1},
			want:         approvalexec.ShellCommandOperation,
		},
		{
			name:         "generic capability alone",
			capabilities: []string{wire.CapabilityCodexShellApprovalV1},
			want:         approvalexec.ShellCommandOperation,
		},
		{
			name:         "legacy capability alone",
			capabilities: []string{wire.CapabilityCodexApprovalBridgeV1},
			want:         approvalexec.GitPushOperation,
		},
		{name: "no capability"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := codexApprovalOperationFor(tt.capabilities); got != tt.want {
				t.Fatalf("codexApprovalOperationFor() = %q, want %q", got, tt.want)
			}
		})
	}
}
