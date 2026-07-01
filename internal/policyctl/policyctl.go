// Package policyctl provides a single ceremony for policy mutations with
// two-phase fail-closed audit (Plan 009 / Plan 010). Every CLI command that
// mutates policy.yaml follows the same sequence:
//
//  1. Load config
//  2. Emit policy.change_requested (abort if audit fails)
//  3. Apply the caller-supplied mutation
//  4. Save config
//  5. Emit policy.changed (best-effort)
//  6. SIGHUP daemon
//
// This package extracts that ceremony so 12+ CLI functions no longer copy-paste
// it. The mutation itself is supplied as a MutationFunc.
package policyctl

import (
	"context"
	"fmt"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/store"
)

// MutationFunc applies a change to the policy config. Return an error to abort
// the mutation (config will not be saved).
type MutationFunc func(cfg *config.PolicyConfig) error

// Controller manages policy mutations with two-phase audit.
type Controller struct {
	policyPath string
	emitter    audit.Emitter
	sighup     func() // signal daemon to reload; nil-safe
}

// New creates a Controller. The sighup function is called after each
// successful mutation to signal the daemon; it may be nil.
func New(policyPath string, emitter audit.Emitter, sighup func()) *Controller {
	return &Controller{
		policyPath: policyPath,
		emitter:    emitter,
		sighup:     sighup,
	}
}

// NewFromDBPath creates a Controller by opening a store at the given DB path.
// The caller must close the returned EventStore. If the store cannot be
// opened, returns an error (policy mutations require audit -- fail-closed).
func NewFromDBPath(policyPath, dbPath string, sighup func()) (*Controller, store.EventStore, error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("policyctl: cannot open store for audit: %w", err)
	}
	return New(policyPath, st, sighup), st, nil
}

// Apply executes a policy mutation with two-phase fail-closed audit:
//
//  1. Load current config from disk
//  2. Emit policy.change_requested (abort if audit fails)
//  3. Apply the mutation
//  4. Save config
//  5. Emit policy.changed (best-effort)
//  6. SIGHUP daemon
func (c *Controller) Apply(ctx context.Context, entity, actor string, detail map[string]string, mutate MutationFunc) error {
	cfg, err := config.LoadOrDefault(c.policyPath)
	if err != nil {
		return fmt.Errorf("policyctl: load config: %w", err)
	}

	return c.applyInner(ctx, cfg, entity, actor, detail, mutate)
}

// ApplyWithConfig is like Apply but uses a pre-loaded config instead of
// loading from disk. Useful when the caller has already loaded and validated
// the config (e.g. for idempotency checks).
func (c *Controller) ApplyWithConfig(ctx context.Context, cfg *config.PolicyConfig, entity, actor string, detail map[string]string, mutate MutationFunc) error {
	return c.applyInner(ctx, cfg, entity, actor, detail, mutate)
}

// applyInner is the shared implementation for Apply and ApplyWithConfig.
func (c *Controller) applyInner(ctx context.Context, cfg *config.PolicyConfig, entity, actor string, detail map[string]string, mutate MutationFunc) error {
	// Phase 1: fail-closed audit -- abort if we cannot record the intent.
	if err := c.emitter.Emit(ctx, audit.Event{
		EventType: audit.PolicyChangeRequested,
		Entity:    entity,
		Actor:     actor,
		Detail:    detail,
	}); err != nil {
		return fmt.Errorf("policyctl: audit emit failed -- aborting: %w", err)
	}

	// Apply the mutation.
	if err := mutate(cfg); err != nil {
		return fmt.Errorf("policyctl: mutation failed: %w", err)
	}

	// Save.
	if err := config.Save(cfg, c.policyPath); err != nil {
		return fmt.Errorf("policyctl: save config: %w", err)
	}

	// Phase 2: best-effort audit -- record that the change was committed.
	_ = c.emitter.Emit(ctx, audit.Event{
		EventType: audit.PolicyChanged,
		Entity:    entity,
		Actor:     actor,
		Detail:    detail,
	})

	// Signal daemon.
	if c.sighup != nil {
		c.sighup()
	}

	return nil
}
