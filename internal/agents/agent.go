// Package agents defines the Agent interface and registry for the three
// supported coding agents: claude-code, codex, and cursor.
//
// Each agent implementation knows how to detect its presence on the machine,
// wire the agentjail hook into its config, reverse that wiring, and report
// its current install status. Orchestration (daemon setup, picker, summary)
// lives in cmd/agentjail/install.go; each agent owns only its own hook wiring.
//
// Env is dependency-injected so agent code and tests never touch the real
// $HOME — pass a temp dir as Env.Home to isolate every test.
package agents

// Agent is the interface every coding-agent implementation must satisfy.
// All methods must be idempotent: calling Install or Uninstall twice must
// converge to the same state as calling it once.
type Agent interface {
	// ID returns the canonical kebab-case identifier used in CLI flags and
	// the registry (e.g. "claude-code", "codex", "cursor").
	ID() string

	// DisplayName returns a human-readable label for use in the picker and
	// status output (e.g. "Claude Code").
	DisplayName() string

	// Detect reports whether this agent is present on the machine described
	// by env. It must not mutate any file.
	Detect(env Env) Detection

	// Install wires the agentjail hook into this agent's configuration,
	// writing files via writeFileAtomic. It is idempotent.
	Install(env Env) error

	// Uninstall removes the agentjail hook entries from this agent's
	// configuration. It is idempotent and must not remove unrelated config.
	Uninstall(env Env) error

	// Status reports the current hook-installation state for this agent.
	Status(env Env) Status
}

// Detection holds the result of an agent presence check.
type Detection struct {
	// Present is true when the agent was found on the machine.
	Present bool

	// Evidence is a short human-readable description of what was found,
	// shown in the interactive picker (e.g. "~/.codex/ exists",
	// "codex on PATH at /usr/local/bin/codex").
	Evidence string
}

// Env carries the injected dependencies that agents use to locate config
// files and binaries. Inject a temp dir as Home in tests to avoid touching
// the real $HOME.
type Env struct {
	// Home is the user's home directory (normally os.UserHomeDir()).
	Home string

	// BinDir is the directory where agentjail binaries are installed
	// (normally ~/.agentjail/bin).
	BinDir string

	// HookBin is the absolute path to the agentjail-hook binary that agents
	// register as their hook command.
	HookBin string

	// LookPath is an injectable replacement for exec.LookPath, used to
	// search for agent binaries on PATH. If nil, callers should set it to
	// exec.LookPath before use.
	LookPath func(string) (string, error)
}

// Status holds the result of an agent's hook-install status check.
type Status struct {
	// Installed is true when the agentjail hook entry is present and active.
	Installed bool

	// Notes contains zero or more human-readable degraded-state annotations
	// (e.g. "features.hooks not enabled", "hook not trusted"). Empty when
	// Installed is true and everything is fully configured.
	Notes []string
}

// Registry returns the ordered list of all supported agents. The order is
// stable and matches the picker display order: claude-code, cursor, codex.
// Codex is wired last so its multi-line manual trust instruction prints at the
// end of the "Wiring hooks" section, not between two other agents' progress lines.
func Registry() []Agent {
	return []Agent{ClaudeCode{}, Cursor{}, Codex{}}
}
