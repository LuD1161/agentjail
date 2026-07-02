package projectpolicy

import (
	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// Status describes what happened to a project overlay during resolution.
type Status string

const (
	// StatusNoOverlay: no ./.agentjail/policy.yaml was found.
	StatusNoOverlay Status = "no_overlay"
	// StatusApplied: a trusted, valid overlay was merged onto the base.
	StatusApplied Status = "applied"
	// StatusUntrusted: an overlay exists but the directory is not trusted (or
	// the file changed since it was trusted); it is ignored, global-only.
	StatusUntrusted Status = "ignored_untrusted"
	// StatusInvalid: a trusted overlay failed to parse/validate; ignored
	// (fail safe -- a broken project file never widens egress and never blocks
	// the session).
	StatusInvalid Status = "ignored_invalid"
)

// Resolution is the outcome of resolving a base policy against a project overlay.
type Resolution struct {
	// Config is the policy the session should enforce: base, or base merged with
	// a trusted overlay (never nil when err is nil).
	Config *config.PolicyConfig
	// Status is the overlay outcome (for audit/logging).
	Status Status
	// OverlayPath is the discovered overlay path (empty when none was found).
	OverlayPath string
}

// Resolve produces the effective policy for a session started in startDir: the
// base (global) policy, additively merged with a `./.agentjail/policy.yaml`
// overlay ONLY IF the overlay exists, the directory is trusted, and the file
// still hashes to the approved value. Untrusted or malformed overlays are
// ignored (global-only) and reported via Status. A discovery/store read error
// is returned but Config still falls back to base so the caller can proceed.
func Resolve(base *config.PolicyConfig, startDir, homeDir, trustPath string) (Resolution, error) {
	o, err := FindOverlay(startDir, homeDir)
	if err != nil {
		return Resolution{Config: base, Status: StatusNoOverlay}, err
	}
	if o == nil {
		return Resolution{Config: base, Status: StatusNoOverlay}, nil
	}

	ts, err := LoadTrustStore(trustPath)
	if err != nil {
		// Malformed trust store -> fail safe: treat the overlay as untrusted.
		return Resolution{Config: base, Status: StatusUntrusted, OverlayPath: o.Path}, err
	}
	if !ts.IsTrusted(o) {
		return Resolution{Config: base, Status: StatusUntrusted, OverlayPath: o.Path}, nil
	}

	overlayCfg, err := config.Load(o.Path)
	if err != nil {
		// Trusted but broken -> ignore it, do not abort the session.
		return Resolution{Config: base, Status: StatusInvalid, OverlayPath: o.Path}, nil
	}

	merged := config.MergeProjectOverlay(base, overlayCfg)
	return Resolution{Config: merged, Status: StatusApplied, OverlayPath: o.Path}, nil
}
