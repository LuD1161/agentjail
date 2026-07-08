// Package main -- launch-time hook-registration reassertion (P11).
//
// ~/.claude/settings.json (and the equivalent Codex/Cursor hook config
// files) hold the agentjail PreToolUse hook registration, and those files
// are agent-writable -- Claude Code itself needs write access to them. A
// prompt-injected agent can therefore delete the agentjail hook entry to
// disable Tier-1 enforcement. Because Claude Code (and Codex/Cursor) only
// read their hook configuration at session START, a deletion made mid-session
// has no effect on the CURRENT session but silently disables enforcement for
// every session launched afterwards -- until something notices and restores
// the entry.
//
// internal/hookwatch already watches for this while the daemon is running
// and re-injects the hook on change, but that is a live, best-effort watcher:
// it does nothing if the daemon was not running, crashed, or the file was
// edited in a window it missed. This file adds a second, unconditional
// guarantee: agentjail-shield re-checks and restores the hook registration
// itself, immediately before every exec, so every shielded launch starts
// with the hook provably present regardless of what happened before.
//
// This is deliberately localized to its own file/functions and called from a
// single spot in main.go (see reassertAgentHook's call site) so it stays a
// clean, independent seam from the IMDS metadata guard that also runs
// pre-exec in main.go.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/LuD1161/agentjail/internal/agents"
	"github.com/LuD1161/agentjail/internal/audit"
)

// agentForCommand maps the resolved agent command (e.g. "claude", "codex",
// "cursor", or an absolute path ending in one of those names) to its Agent
// implementation in internal/agents. Only agents with a real hook-
// registration mechanism are matched here; anything unrecognized returns
// ok=false so the caller skips the reassert step gracefully instead of
// guessing at a config shape it doesn't own.
func agentForCommand(agentCmd string) (agents.Agent, bool) {
	switch filepath.Base(agentCmd) {
	case "claude":
		return agents.ClaudeCode{}, true
	case "codex":
		return agents.Codex{}, true
	case "cursor", "cursor-agent":
		return agents.Cursor{}, true
	default:
		return nil, false
	}
}

// reassertAgentHook re-asserts the agentjail hook registration for the agent
// about to be exec'd. Called once from main, right before runShield/exec.
//
// Fail-open by design: this is a defense-in-depth re-assertion of config
// that agentjail itself already wrote once (during `agentjail install`), not
// a security boundary that gates the launch. A failure to re-assert it (disk
// full, permission denied, unreadable/corrupt settings file) is warned about
// loudly on stderr and audited, but must NOT block the agent from launching
// -- refusing to launch over a settings-file write failure would brick every
// session for a problem the daemon's live hookwatch watcher and the next
// shield launch can also still repair. Fail-closed here would turn a
// self-protection nicety into a new denial-of-service surface, which is a
// worse trade for a Tier-1 defense-in-depth control than for the credential
// or policy path (which do fail closed).
func reassertAgentHook(ctx context.Context, agentCmd string, emitter audit.Emitter) {
	agent, ok := agentForCommand(agentCmd)
	if !ok {
		// Agent has no known hook-registration mechanism (or we don't
		// recognize the command) -- nothing to reassert, skip silently.
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: hook reassert: cannot determine home directory: %v\n", err)
		return
	}

	env := agents.Env{
		Home:    home,
		BinDir:  filepath.Join(home, ".agentjail", "bin"),
		HookBin: filepath.Join(home, ".agentjail", "bin", "agentjail-hook"),
		CLIBin:  filepath.Join(home, ".agentjail", "bin", "agentjail"),
	}

	changed, err := agents.EnsureHookRegistered(agent, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: WARNING: could not verify/restore %s hook registration: %v\n", agent.DisplayName(), err)
		fmt.Fprintln(os.Stderr, "agentjail-shield: continuing launch anyway (fail-open) -- run 'agentjail install' to repair manually")
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ShieldFailed,
			Entity:    agent.ID(),
			Detail:    map[string]string{"stage": "hook_reassert", "error": err.Error()},
			Actor:     "shield",
		})
		return
	}
	if !changed {
		// Already correctly registered -- the common case. No log noise, no
		// audit event, matching hookwatch's own quiet-when-healthy behavior.
		return
	}

	fmt.Fprintf(os.Stderr, "agentjail-shield: WARNING: %s hook registration was missing or altered -- restored before launch\n", agent.DisplayName())
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.HookReinjected,
		Entity:    agent.ID(),
		Detail:    map[string]string{"agent": agent.ID(), "actor": "shield"},
		Actor:     "shield",
	})
}
