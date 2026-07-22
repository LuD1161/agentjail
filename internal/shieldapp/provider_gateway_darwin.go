//go:build darwin

package shieldapp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/captureproxy"
	"github.com/LuD1161/agentjail/internal/mitm"
)

// providerGatewayWanted reports whether agentPath names a registered,
// verified provider AND the capture gateway is enabled for cfg. Shared by
// the tunnel path (which must open its capture store before knowing MITM's
// own outcome, see A0) and startProviderGateway itself, so the two checks
// can never drift. See ADR 0109-baseurl-capture-gateway.
func providerGatewayWanted(cfg *config.PolicyConfig, agentPath string) (captureproxy.Provider, bool) {
	prov, ok := captureproxy.Lookup(filepath.Base(agentPath))
	if !ok || !prov.Caps.Verified || !prov.Caps.BaseURLEnv {
		return captureproxy.Provider{}, false
	}
	return prov, captureGatewayEnabled(cfg)
}

// startProviderGateway detects a registered LLM provider agent and, if the
// capture gateway is enabled, routes its base-URL env var through a local
// loopback capture gateway (internal/captureproxy) so its /v1/messages traffic is
// recorded even where transparent MITM cannot see it (AGE-259). rec/bodies
// are caller-owned so the tunnel and non-tunnel darwin paths can share one
// RequestStore/BodyStore with their own MITM posture (if any) -- the gateway
// itself never depends on MITM succeeding. See ADR 0109-baseurl-capture-
// gateway, A0/A1.
//
// started=false, err=nil means "nothing to do" (no provider, or the gateway
// is disabled) -- not a failure. A non-nil err means the gateway was wanted
// but could not be started; callers must fail closed (refuse launch), never
// silently continue uncaptured.
func startProviderGateway(ctx context.Context, cfg *config.PolicyConfig, agentPath string, rec captureproxy.Recorder, bodies *mitm.BodyStore, sessionID string, logger *slog.Logger, emitter audit.Emitter) (env map[string]string, closeFn func() error, started bool, err error) {
	prov, wanted := providerGatewayWanted(cfg, agentPath)
	if !wanted {
		return nil, nil, false, nil
	}

	// Guard cfg == nil explicitly rather than deref cfg.Network.AllowedHosts:
	// nil cfg means empty allowlist + provider-default target only.
	var allowlist []string
	if cfg != nil {
		allowlist = cfg.Network.AllowedHosts
	}
	inherited := os.Getenv(prov.BaseURLEnvVar)
	target, terr := captureproxy.ResolveForwardTarget(inherited, prov, allowlist)
	if terr != nil {
		emitGatewayStartFailed(ctx, emitter, sessionID, prov, "target_rejected")
		return nil, nil, false, fmt.Errorf("capture gateway target rejected for %s: %w", prov.Name, terr)
	}

	agent, cwd := sessionMeta(agentPath)
	gw := captureproxy.New(target, rec, captureproxy.Options{
		SessionID: sessionID,
		OwnerPID:  os.Getpid(),
		Agent:     agent,
		Cwd:       cwd,
		Logger:    logger,
		Bodies:    bodies,
	})
	baseURL, gerr := gw.Start(ctx)
	if gerr != nil {
		_ = gw.Close()
		emitGatewayStartFailed(ctx, emitter, sessionID, prov, "start")
		return nil, nil, false, fmt.Errorf("capture gateway failed to start for %s: %w", prov.Name, gerr)
	}

	envVars := map[string]string{prov.BaseURLEnvVar: baseURL}
	if inherited != "" {
		envVars["AGENTJAIL_ORIGINAL_"+prov.BaseURLEnvVar] = inherited
	}
	emitGatewayProviderRouted(ctx, emitter, sessionID, prov)
	logger.Info("capture gateway ON - "+prov.Name+" LLM API routed through local plaintext capture",
		"upstream", prov.UpstreamHost, "session", sessionID)
	return envVars, gw.Close, true, nil
}
