package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/LuD1161/agentjail/internal/hostproxy"
	"github.com/LuD1161/agentjail/internal/wire"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:                "proxy -- <command> [args...]",
	Short:              "Run one approved non-interactive command outside the shield",
	DisableFlagParsing: true,
	Long: `Run one exact command through the unsandboxed AgentJail daemon on Linux or
macOS after a native allow-once approval. The command receives no stdin or TTY.
It runs with the daemon service environment, not your interactive login-shell
environment. Unsupported platforms and missing approval/session state fail closed.`,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runHostProxy(cmd, args))
	},
}

func init() { rootCmd.AddCommand(proxyCmd) }

func runHostProxy(cmd *cobra.Command, args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "agentjail proxy: command is required after --")
		return 2
	}
	proof := hostproxy.Proof(os.Getenv(hostproxy.ProofEnvironmentName))
	executable := os.Getenv(hostproxy.TargetEnvironmentName)
	if proof == "" || executable == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "agentjail proxy: no native one-time approval is available")
		return 1
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: working directory: %v\n", err)
		return 1
	}
	target := hostproxy.Target{Executable: executable, Argv: append([]string(nil), args...)}
	if decision := hostproxy.Evaluate(target); decision.Action != hostproxy.ActionAsk {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: %s\n", decision.Reason)
		return 1
	}
	conn, err := net.DialTimeout("unix", wire.DefaultSocketPath(), 500*time.Millisecond)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: policy daemon unavailable: %v\n", err)
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(hostproxy.DefaultTimeout + 5*time.Second))
	if err := json.NewEncoder(conn).Encode(hostproxy.WireRequest{
		Type:    hostproxy.RequestType,
		Request: hostproxy.Request{Proof: proof, Target: target, CWD: cwd},
	}); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: request: %v\n", err)
		return 1
	}
	var response hostproxy.WireResponse
	if err := json.NewDecoder(io.LimitReader(conn, hostproxy.MaxResponseBytes)).Decode(&response); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: response: %v\n", err)
		return 1
	}
	if !response.OK {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: %s\n", response.Error)
		return 1
	}
	_, _ = cmd.OutOrStdout().Write(response.Result.Stdout)
	_, _ = cmd.ErrOrStderr().Write(response.Result.Stderr)
	if response.Result.TimedOut {
		fmt.Fprintln(cmd.ErrOrStderr(), "agentjail proxy: command timed out")
		return 124
	}
	if response.Result.Truncated {
		fmt.Fprintln(cmd.ErrOrStderr(), "agentjail proxy: combined output limit exceeded")
		return 125
	}
	if response.Result.ExitCode < 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "agentjail proxy: %s\n", response.Result.Reason)
		return 1
	}
	return response.Result.ExitCode
}
