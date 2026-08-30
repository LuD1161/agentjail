package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/ui"
)

const (
	installMCPDiscoveryReadyAttempts = 20
	installMCPDiscoveryReadyDelay    = 100 * time.Millisecond
)

type installMCPDiscoveryDependencies struct {
	loadToken   func() (string, error)
	discover    func(string, string, time.Duration) (grantctl.MCPToolsDiscoveryV1, error)
	socketReady func(string) bool
	wait        func(time.Duration)
	attempts    int
}

func defaultInstallMCPDiscoveryDependencies() installMCPDiscoveryDependencies {
	cli := defaultMCPToolDiscoveryDependencies()
	return installMCPDiscoveryDependencies{
		loadToken: cli.loadToken,
		discover:  cli.discover,
		socketReady: func(path string) bool {
			info, err := os.Stat(path)
			return err == nil && info.Mode()&os.ModeSocket != 0
		},
		wait:     time.Sleep,
		attempts: installMCPDiscoveryReadyAttempts,
	}
}

type daemonMCPInstallDependencies struct {
	preamble func(string, io.Writer, []string) error
	discover func(io.Writer, installMCPDiscoveryDependencies)
}

func installDaemonWithMCPDiscovery(home string, out io.Writer, mcpSeed []string) error {
	return installDaemonWithMCPDiscoveryDependencies(home, out, mcpSeed, daemonMCPInstallDependencies{
		preamble: installDaemonPreamble,
		discover: runInstallMCPDiscovery,
	})
}

func installDaemonWithMCPDiscoveryDependencies(home string, out io.Writer, mcpSeed []string, dependencies daemonMCPInstallDependencies) error {
	if dependencies.preamble == nil || dependencies.discover == nil {
		return fmt.Errorf("install orchestration unavailable")
	}
	if err := dependencies.preamble(home, out, mcpSeed); err != nil {
		return err
	}
	dependencies.discover(out, defaultInstallMCPDiscoveryDependencies())
	return nil
}

func runInstallMCPDiscovery(out io.Writer, dependencies installMCPDiscoveryDependencies) {
	u := ui.New(out)
	fmt.Fprintln(out)
	fmt.Fprintln(out, u.Section(u.Emoji("🔎  ")+"Cataloging MCP tools"))

	if dependencies.loadToken == nil || dependencies.discover == nil || dependencies.socketReady == nil || dependencies.wait == nil || dependencies.attempts < 1 {
		fmt.Fprintln(out, "      "+u.Badge("warn", "tool discovery unavailable — retry later with 'agentjail mcp tool discover'"))
		return
	}

	socketPath := grantctl.ControlSocketPath()
	var token string
	ready := false
	for attempt := 0; attempt < dependencies.attempts; attempt++ {
		loaded, err := dependencies.loadToken()
		if err == nil && dependencies.socketReady(socketPath) {
			token = loaded
			ready = true
			break
		}
		if attempt+1 < dependencies.attempts {
			dependencies.wait(installMCPDiscoveryReadyDelay)
		}
	}
	if !ready {
		fmt.Fprintln(out, "      "+u.Badge("warn", "daemon discovery authority is not ready — retry later with 'agentjail mcp tool discover'"))
		return
	}

	discovery, err := dependencies.discover(socketPath, token, mcpToolDiscoveryTimeout)
	if err != nil {
		fmt.Fprintln(out, "      "+u.Badge("warn", "tool discovery could not complete — retry later with 'agentjail mcp tool discover'"))
		return
	}

	tools := 0
	statuses := make(map[grantctl.MCPDiscoveryStatus]int, 4)
	for _, server := range discovery.Servers {
		tools += len(server.Tools)
		statuses[server.Status]++
	}
	if len(discovery.Servers) == 0 {
		fmt.Fprintln(out, "      "+u.Badge("dim", "no configured MCP servers found"))
		return
	}

	fmt.Fprintln(out, "      "+u.Badge("ok", fmt.Sprintf("%d tool(s) cataloged across %d configured server(s)", tools, len(discovery.Servers))))
	fmt.Fprintf(out, "      %d connected", statuses[grantctl.MCPDiscoveryConnected])
	if count := statuses[grantctl.MCPDiscoveryAuthRequired]; count > 0 {
		fmt.Fprintf(out, " · %d need authentication", count)
	}
	if count := statuses[grantctl.MCPDiscoveryUnreachable]; count > 0 {
		fmt.Fprintf(out, " · %d unreachable", count)
	}
	if count := statuses[grantctl.MCPDiscoveryTimeout]; count > 0 {
		fmt.Fprintf(out, " · %d timed out", count)
	}
	fmt.Fprintln(out)
}
