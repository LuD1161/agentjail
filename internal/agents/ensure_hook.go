package agents

// EnsureHookRegistered re-asserts an agent's agentjail hook registration,
// restoring it if it is missing or was altered. It exists for callers (e.g.
// agentjail-shield) that need to guarantee the hook is wired at a specific
// moment -- immediately before exec'ing the agent -- regardless of what a
// prior session did to the settings file (P11: Claude Code and friends only
// read hook config at session START, so a prompt-injected agent that deletes
// the entry silently disables enforcement for every future session unless
// something re-asserts it at the next launch).
//
// It delegates entirely to the agent's own Install method. Install is
// already idempotent (a no-op when the hook is already correctly wired) and
// preserves every other key in the settings file, so this wrapper cannot
// drift from what `agentjail install` considers "correctly wired" -- there
// is exactly one place (each Agent's Install) that owns the on-disk JSON
// shape; this function does not duplicate it.
//
// changed reports whether the call actually modified the file. A nil error
// with changed=false means the hook was already present and nothing was
// written -- the common case on every launch. It is computed by comparing
// Status before and after Install rather than growing the Agent interface,
// so any current or future Agent implementation gets it for free.
func EnsureHookRegistered(a Agent, env Env) (changed bool, err error) {
	before := a.Status(env)
	if err := a.Install(env); err != nil {
		return false, err
	}
	return !before.Installed, nil
}
