package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/wire"
	"github.com/spf13/cobra"
)

func TestRunApprovalExecCommandWritesBrokerFailure(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	err := runApprovalExecCommand(cmd, approvalexec.ChallengeID("not-a-challenge"), approvalexec.GitPushOperation, "needs review")
	if err == nil {
		t.Fatal("malformed challenge succeeded")
	}
	if !strings.Contains(stderr.String(), "malformed challenge") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunApprovalExecRejectsUnsupportedOperation(t *testing.T) {
	err := runApprovalExec("not-a-challenge", approvalexec.Operation("package-publish"), "needs review")
	if err == nil || !strings.Contains(err.Error(), "unsupported operation") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunApprovalExecRequiresReason(t *testing.T) {
	challenge := approvalexec.ChallengeID("A" + strings.Repeat("B", 42))
	err := runApprovalExec(challenge, approvalexec.ShellCommandOperation, "")
	if err == nil || !strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("error = %v, want missing reason rejection", err)
	}
}

func TestRunApprovalExecRequiresOperationAndChallenge(t *testing.T) {
	tests := []struct {
		name      string
		challenge approvalexec.ChallengeID
		operation approvalexec.Operation
		want      string
	}{
		{name: "operation", want: "--operation is required"},
		{name: "challenge", operation: approvalexec.ShellCommandOperation, want: "--challenge is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runApprovalExec(tt.challenge, tt.operation, "needs review")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestApprovalExecHelpDocumentsReasonContract(t *testing.T) {
	help := strings.Join([]string{
		approvalExecCmd.Use,
		approvalExecCmd.Long,
		approvalExecCmd.Example,
		approvalExecCmd.Flags().Lookup("reason").Usage,
	}, "\n")
	for _, want := range []string{
		"--reason EXPLANATION",
		"displayed with this command in Codex's native",
		"editing any value invalidates the approval",
		"--reason \"publishing to a package registry is irreversible; confirm intent\"",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("approval-exec help does not contain %q:\n%s", want, help)
		}
	}
}

func TestRunApprovalExecSendsSupportedOperation(t *testing.T) {
	challenge := approvalexec.ChallengeID("A" + strings.Repeat("B", 42))
	reason := approvalexec.Reason("publish the release candidate")
	for _, operation := range []approvalexec.Operation{
		approvalexec.GitPushOperation,
		approvalexec.ShellCommandOperation,
	} {
		t.Run(string(operation), func(t *testing.T) {
			home, err := os.MkdirTemp("/tmp", "ajap-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(home) })
			t.Setenv("HOME", home)
			socketPath := wire.DefaultSocketPath()
			if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			received := make(chan approvalexec.WireRedeemRequest, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				var req approvalexec.WireRedeemRequest
				if json.NewDecoder(conn).Decode(&req) == nil {
					received <- req
				}
				_ = json.NewEncoder(conn).Encode(approvalexec.WireRedeemResponse{Error: "declined"})
			}()

			err = runApprovalExec(challenge, operation, reason)
			if err == nil || !strings.Contains(err.Error(), "declined") {
				t.Fatalf("runApprovalExec() error = %v, want daemon rejection", err)
			}
			got := <-received
			if got.Type != approvalexec.RedeemRequestType || got.ChallengeID != challenge || got.Operation != operation || got.Reason != reason {
				t.Fatalf("redeem request = %#v", got)
			}
		})
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
