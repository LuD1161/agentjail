package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/wire"
	"github.com/spf13/cobra"
)

var approvalChallenge string
var approvalOperation string

var approvalExecCmd = &cobra.Command{
	Use:    "approval-exec",
	Short:  "Redeem a one-use Codex approval (internal)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runApprovalExecCommand(cmd, approvalexec.ChallengeID(approvalChallenge), approvalexec.Operation(approvalOperation))
	},
}

func init() {
	approvalExecCmd.Flags().StringVar(&approvalChallenge, "challenge", "", "One-use approval challenge")
	approvalExecCmd.Flags().StringVar(&approvalOperation, "operation", "", "Typed approval operation")
	_ = approvalExecCmd.MarkFlagRequired("challenge")
	_ = approvalExecCmd.MarkFlagRequired("operation")
	rootCmd.AddCommand(approvalExecCmd)
}

func runApprovalExec(challengeID approvalexec.ChallengeID, operation approvalexec.Operation) error {
	if !approvalexec.ValidOperation(operation) {
		return fmt.Errorf("agentjail approval-exec: unsupported operation")
	}
	invocation := approvalexec.BrokerInvocation{Operation: operation, ChallengeID: challengeID}
	parsed, ok := approvalexec.ParseBrokerCommand(approvalexec.BrokerCommand(invocation))
	if !ok || parsed != invocation {
		return fmt.Errorf("agentjail approval-exec: malformed challenge")
	}
	conn, err := net.DialTimeout("unix", wire.DefaultSocketPath(), 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("agentjail approval-exec: policy daemon unavailable: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return fmt.Errorf("agentjail approval-exec: set deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(approvalexec.WireRedeemRequest{
		Type: approvalexec.RedeemRequestType, ChallengeID: challengeID, Operation: operation,
	}); err != nil {
		return fmt.Errorf("agentjail approval-exec: redeem: %w", err)
	}
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("agentjail approval-exec: redeem: %w", err)
		}
		return errors.New("agentjail approval-exec: daemon closed without a redemption response")
	}
	var resp approvalexec.WireRedeemResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return fmt.Errorf("agentjail approval-exec: invalid daemon response: %w", err)
	}
	if !resp.OK || resp.Command == "" {
		return fmt.Errorf("agentjail approval-exec: %s", resp.Error)
	}
	if err := os.Chdir(resp.CWD); err != nil {
		return fmt.Errorf("agentjail approval-exec: restore working directory: %w", err)
	}
	shell := approvalExecShell(os.Getenv)
	return syscall.Exec(shell, []string{filepath.Base(shell), "-lc", string(resp.Command)}, os.Environ())
}

// approvalExecShell follows the host login shell selected for the Codex
// session, retaining shell syntax and login initialization for the redeemed
// command. An absent or non-absolute value fails back to the portable shell.
func approvalExecShell(getenv func(string) string) string {
	shell := getenv("SHELL")
	if filepath.IsAbs(shell) {
		return shell
	}
	return "/bin/sh"
}

func runApprovalExecCommand(cmd *cobra.Command, challengeID approvalexec.ChallengeID, operation approvalexec.Operation) error {
	err := runApprovalExec(challengeID, operation)
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), err)
	}
	return err
}
