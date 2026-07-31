package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/spf13/cobra"
)

func TestRunApprovalExecCommandWritesBrokerFailure(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	err := runApprovalExecCommand(cmd, approvalexec.ChallengeID("not-a-challenge"))
	if err == nil {
		t.Fatal("malformed challenge succeeded")
	}
	if !strings.Contains(stderr.String(), "malformed challenge") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestApprovalExecShellUsesAbsoluteSessionShell(t *testing.T) {
	tests := []struct {
		name  string
		shell string
		want  string
	}{
		{name: "absolute shell", shell: "/bin/zsh", want: "/bin/zsh"},
		{name: "missing shell", want: "/bin/sh"},
		{name: "relative shell", shell: "zsh", want: "/bin/sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := approvalExecShell(func(string) string { return tt.shell }); got != tt.want {
				t.Fatalf("shell = %q, want %q", got, tt.want)
			}
		})
	}
}
