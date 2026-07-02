//go:build darwin

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// daemonSocketPath returns the Unix socket path for the agentjail-daemon RPC.
func daemonSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.sock"
	}
	return filepath.Join(home, ".agentjail", "daemon-ns.sock")
}

// generateSessionID generates a random hex session ID for daemon RPC calls.
func generateSessionID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("shield-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// startTunnelDarwin activates the utun-based transparent tunnel by calling the
// agentjail-daemon RPC. The daemon (running as root via LaunchDaemon) creates
// a kernel utun device, configures routes, and runs the gateway + DNS-VIP
// server — no Network Extension app bundle required.
//
// Returns (cleanup, true) on success. Returns (nil, false) if the daemon is
// not running or the RPC fails; the caller should fall back to netproxy mode.
func startTunnelDarwin(ctx context.Context) (cleanup func(), ready bool) {
	logger := slog.Default()
	_ = ctx

	sockPath := daemonSocketPath()
	sessionID := generateSessionID()

	nsResp, err := requestNamespace(sockPath, sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield INFO: utun tunnel unavailable (daemon RPC: %v)\n"+
				"  Is agentjail-daemon running? Falling back to netproxy mode.\n", err)
		return nil, false
	}

	logger.Info("utun tunnel active",
		"session_id", sessionID,
		"utun", nsResp.UTunName,
		"gateway_ip", nsResp.GatewayIP,
	)
	fmt.Fprintf(os.Stderr,
		"agentjail-shield INFO: utun tunnel active (utun=%s gateway=%s)\n",
		nsResp.UTunName, nsResp.GatewayIP)

	cleanup = func() {
		if err := destroyNamespace(sockPath, sessionID); err != nil {
			fmt.Fprintf(os.Stderr,
				"agentjail-shield WARNING: failed to destroy utun tunnel: %v\n", err)
		}
	}
	return cleanup, true
}

// cleanupTunnelDarwin safely calls the tunnel cleanup function if non-nil.
func cleanupTunnelDarwin(cleanup func()) {
	if cleanup != nil {
		cleanup()
	}
}
