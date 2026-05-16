# Package data.agentpolicy.lib.exec.rm_rf
#
# Discoverable, self-contained library port of the `rm -rf` rule that has
# lived inside `agentjail.default` since the original single-package layout.
# Lifted into its own package so callers can compose the predicate without
# pulling in the umbrella decision wiring.
#
# Pattern follows Cerbos' "one rule per resource module" organization (see
# Cerbos resource policy docs: a policy file owns one resource's actions,
# keeping rules unit-testable in isolation rather than buried in a monolith).
#
# Input contract (matches the existing default.rego shape):
#   input.hook            == "exec"
#   input.program         == "rm"
#   input.flags           : array<string>   # parsed short/long flags
#   input.paths_resolved  : array<string>   # absolute, $HOME / ~ pre-expanded
#   input.context.home    : string          # absolute home dir
#
# Output:
#   decision := {"action": "deny", "rule_id": "no-recursive-delete-of-protected-paths"}
# when a protected path is targeted by a recursive + force `rm`; otherwise
# the rule is silent (no default; callers compose with `else`).
package agentpolicy.lib.exec.rm_rf

import future.keywords.in
import future.keywords.if

# The exported predicate. Callers do:
#
#   import data.agentpolicy.lib.exec.rm_rf
#   decision := rm_rf.decision { ... } else := ...
decision := r if {
	input.hook == "exec"
	input.program == "rm"
	some f1 in input.flags
	f1 in {"-r", "-R", "--recursive"}
	some f2 in input.flags
	f2 in {"-f", "--force"}
	some p in input.paths_resolved
	protected_path(p)
	r := {"action": "deny", "rule_id": "no-recursive-delete-of-protected-paths"}
}

# protected_path is exported so other lib modules can reuse the same
# definition rather than copy-pasting the path list. Order of clauses is
# irrelevant (Rego ORs them).

# Root.
protected_path(p) if {
	p == "/"
}

# The user's home, exactly.
protected_path(p) if {
	p == input.context.home
}

# Anything below the user's home (covers $HOME/.ssh, ~/.config, etc. once
# the caller has expanded ~ and $HOME into input.context.home).
protected_path(p) if {
	startswith(p, sprintf("%s/", [input.context.home]))
}

# macOS multi-user root.
protected_path(p) if {
	startswith(p, "/Users/")
}

# System directories that should never be recursively force-deleted from a
# coding agent's shell, regardless of who owns them.
protected_path(p) if {
	p == "/etc"
}

protected_path(p) if {
	startswith(p, "/etc/")
}

protected_path(p) if {
	p == "/usr"
}

protected_path(p) if {
	startswith(p, "/usr/")
}

protected_path(p) if {
	p == "/var"
}

protected_path(p) if {
	startswith(p, "/var/")
}

protected_path(p) if {
	p == "/opt"
}

protected_path(p) if {
	startswith(p, "/opt/")
}
