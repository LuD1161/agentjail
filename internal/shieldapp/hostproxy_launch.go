package shieldapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

func registerHostProxyLaunch(ctx context.Context, ctlToken string, tokenErr error, env []string, emitter audit.Emitter) bool {
	root, err := os.Getwd()
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	pathValue := environmentValue(env, "PATH")
	if tokenErr == nil && err == nil && pathValue != "" {
		err = grantctl.RegisterSessionLaunch(grantctl.ControlSocketPath(), ctlToken, os.Getpid(), root, pathValue, 500*time.Millisecond)
	} else if tokenErr != nil {
		err = tokenErr
	}
	if err == nil {
		return true
	}
	fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: host proxy unavailable for this session: %v\n", err)
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.HostProxySessionRegisterFailed, Actor: "shield",
		Detail: map[string]string{"reason": "session launch registration failed"},
	})
	return false
}

func unregisterHostProxyLaunch(registered bool, ctlToken string) {
	if registered {
		_ = grantctl.UnregisterSessionLaunch(grantctl.ControlSocketPath(), ctlToken, os.Getpid(), 500*time.Millisecond)
	}
}

func registerConnectorLaunch(ctlToken string, env []string, netproxySessionID, capability string) bool {
	if capability == "" {
		return true
	}
	root, err := os.Getwd()
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	pathValue := environmentValue(env, "PATH")
	if err != nil || pathValue == "" {
		return false
	}
	return grantctl.RegisterSessionLaunchConnector(grantctl.ControlSocketPath(), ctlToken, os.Getpid(), root, pathValue, netproxySessionID, capability, 500*time.Millisecond) == nil
}

func environmentValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}
