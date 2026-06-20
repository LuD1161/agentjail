// Package main is agentjail-shield. This file contains platform-independent
// helpers for locating and starting agentjail-netproxy as a child process.
//
// The netproxy binary itself (cmd/agentjail-netproxy) is stdlib-only and
// portable.  These helpers are shared by the macOS and Linux shield
// implementations so both platforms start the proxy the same way.

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// netproxyDefaultAddr is the address the netproxy listens on when started by
// the shield.  It must match the address the agent connects to via
// HTTPS_PROXY.  Shared between macOS (Seatbelt) and Linux (Landlock).
const netproxyDefaultAddr = "127.0.0.1:9100"

// findNetproxyBinary locates the agentjail-netproxy binary.
//
// Search order (first hit wins):
//  1. $AGENTJAIL_NETPROXY env var
//  2. ~/.agentjail/bin/agentjail-netproxy
//  3. Sibling of the shield binary itself (filepath.Dir(os.Args[0]))
func findNetproxyBinary() (string, error) {
	if envPath := os.Getenv("AGENTJAIL_NETPROXY"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, nil
		}
		return "", fmt.Errorf("$AGENTJAIL_NETPROXY=%s does not exist", envPath)
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		candidate := filepath.Join(home, ".agentjail", "bin", "agentjail-netproxy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	if len(os.Args) > 0 && os.Args[0] != "" {
		candidate := filepath.Join(filepath.Dir(os.Args[0]), "agentjail-netproxy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("agentjail-netproxy binary not found; " +
		"set $AGENTJAIL_NETPROXY, install to ~/.agentjail/bin/, " +
		"or place alongside agentjail-shield")
}

// startNetproxy starts agentjail-netproxy as a child process with the given
// policy path, waits up to 200 ms for it to bind on proxyAddr, and returns
// the running *exec.Cmd.  Caller is responsible for calling cmd.Process.Kill()
// on exit.
func startNetproxy(netproxyPath, proxyAddr, policyPath string) (*exec.Cmd, error) {
	cmd := exec.Command(netproxyPath,
		"--addr="+proxyAddr,
		"--policy="+policyPath,
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start netproxy: %w", err)
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 20*time.Millisecond)
		if err == nil {
			conn.Close()
			fmt.Fprintf(os.Stderr, "agentjail-shield INFO: netproxy started (pid=%d) listening on %s\n", cmd.Process.Pid, proxyAddr)
			return cmd, nil
		}
		time.Sleep(20 * time.Millisecond)
	}

	_ = cmd.Process.Kill()
	return nil, fmt.Errorf("netproxy did not bind on %s within 200ms; per-host enforcement unavailable", proxyAddr)
}

// proxyEnvVars returns the HTTPS_PROXY, HTTP_PROXY, and ALL_PROXY environment
// variables pointing at proxyAddr.  Used by both macOS and Linux shield
// implementations to route the agent's HTTPS traffic through netproxy.
func proxyEnvVars(proxyAddr string) []string {
	proxyURL := "http://" + proxyAddr
	return []string{
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"ALL_PROXY=" + proxyURL,
	}
}

// cleanupNetproxy terminates and reaps the netproxy child process to prevent
// zombies.  Safe to call with a nil cmd.
func cleanupNetproxy(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
}
