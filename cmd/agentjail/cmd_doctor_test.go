package main

import (
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/sshagent"
)

func TestDoctorSSHAgentCheck(t *testing.T) {
	tests := []struct {
		name       string
		status     sshagent.Status
		wantStatus string
		wantSubstr string
	}{
		{
			name: "ready",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessReady,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "ok",
			wantSubstr: "loaded",
		},
		{
			name: "keys on disk but agent has none loaded",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoKeys,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "ssh-add",
		},
		{
			name: "no agent reachable, keys on disk",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoAgent,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "ssh-add",
		},
		{
			name: "no keys on disk",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoAgent,
				KeysOnDisk: false,
			},
			wantStatus: "skip",
			wantSubstr: "no ssh keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := sshAgentCheck(tt.status)
			if c.label != "ssh-agent" {
				t.Errorf("label = %q, want %q", c.label, "ssh-agent")
			}
			if c.status != tt.wantStatus {
				t.Errorf("status = %q, want %q", c.status, tt.wantStatus)
			}
			if !strings.Contains(c.detail, tt.wantSubstr) {
				t.Errorf("detail = %q, want substring %q", c.detail, tt.wantSubstr)
			}
			if c.status == "fail" {
				t.Errorf("sshAgentCheck must never return status=fail (user env state, not an install defect)")
			}
		})
	}
}
