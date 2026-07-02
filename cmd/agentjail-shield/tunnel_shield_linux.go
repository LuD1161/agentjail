//go:build linux

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

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/tunnel"
)

func daemonSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.sock"
	}
	return filepath.Join(home, ".agentjail", "daemon-ns.sock")
}

func generateSessionID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("shield-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

func startTunnel(ctx context.Context, sessionID string) (gw *tunnel.Gateway, cancel context.CancelFunc, ready bool) {
	logger := slog.Default()
	sockPath := daemonSocketPath()

	privKey, _, err := tunnel.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield WARNING: tunnel key generation failed: %v\n"+
				"  Falling back to netproxy mode.\n", err)
		return nil, nil, false
	}

	nsResp, err := requestNamespace(sockPath, sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield WARNING: could not request namespace from daemon: %v\n"+
				"  Is agentjail-daemon running? Falling back to netproxy mode.\n", err)
		return nil, nil, false
	}

	_, agentPubKey, err := tunnel.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield WARNING: tunnel agent key generation failed: %v\n"+
				"  Falling back to netproxy mode.\n", err)
		_ = destroyNamespace(sockPath, sessionID)
		return nil, nil, false
	}
	_ = nsResp

	cfg := tunnel.Config{
		PrivateKey:    privKey,
		ListenPort:    51820,
		PeerPublicKey: agentPubKey,
		TunnelAddr:    "10.78.0.1/16",
	}

	registry := dnsvip.NewRegistry()
	dnsServer := dnsvip.NewServer("10.78.0.1:53", registry)

	tunnelCtx, tunnelCancelFn := context.WithCancel(ctx)
	go func() {
		if err := dnsServer.ListenAndServe(tunnelCtx); err != nil && tunnelCtx.Err() == nil {
			logger.Error("DNS-VIP server error", "err", err)
		}
	}()

	gateway, err := tunnel.NewGateway(cfg, registry, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield WARNING: could not create tunnel gateway: %v\n"+
				"  Falling back to netproxy mode.\n", err)
		tunnelCancelFn()
		_ = dnsServer.Close()
		_ = destroyNamespace(sockPath, sessionID)
		return nil, nil, false
	}

	go func() {
		if err := gateway.ListenAndServe(tunnelCtx); err != nil && tunnelCtx.Err() == nil {
			logger.Error("tunnel gateway error", "err", err)
		}
	}()

	return gateway, tunnelCancelFn, true
}

func cleanupTunnel(gw *tunnel.Gateway, cancel context.CancelFunc, sessionID string) {
	if cancel != nil {
		cancel()
	}
	if gw != nil {
		_ = gw.Close()
	}
	_ = destroyNamespace(daemonSocketPath(), sessionID)
}
