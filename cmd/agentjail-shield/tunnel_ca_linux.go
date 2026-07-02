//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netns"
)

func setupTunnelCA(ns *netns.Namespace) (caDir string, cleanup func(), err error) {
	caDir, err = os.MkdirTemp("", "agentjail-tunnel-ca-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temp CA dir: %w", err)
	}

	cleanupFn := func() { os.RemoveAll(caDir) }

	if _, _, err := mitm.GenerateCA(caDir); err != nil {
		cleanupFn()
		return "", func() {}, fmt.Errorf("generate tunnel CA: %w", err)
	}

	certPath := filepath.Join(caDir, "root.crt")
	if err := ns.InjectCA(certPath); err != nil {
		cleanupFn()
		return "", func() {}, fmt.Errorf("inject CA into namespace: %w", err)
	}

	return caDir, cleanupFn, nil
}
