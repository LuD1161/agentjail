package agentjail.default

import future.keywords.in
import future.keywords.if

# Output shape:
#   decision := {"action": "deny"|"ask"|"allow", "rule_id": "..."}
default decision := {"action": "allow"}

# --- exec rules ---

rule_recursive_force_in_protected_paths := r if {
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

rule_find_delete_in_home := r if {
	input.hook == "exec"
	input.program == "find"
	"-delete" in input.argv_raw
	some p in input.paths_resolved
	startswith(p, sprintf("%s/", [input.context.home]))
	r := {"action": "deny", "rule_id": "no-find-delete-in-home"}
}

# Also accept the long form `--delete` for find.
rule_find_delete_in_home := r if {
	input.hook == "exec"
	input.program == "find"
	"--delete" in input.argv_raw
	some p in input.paths_resolved
	startswith(p, sprintf("%s/", [input.context.home]))
	r := {"action": "deny", "rule_id": "no-find-delete-in-home"}
}

# --- file rules ---

rule_dotfile_ask := r if {
	input.hook == "file"
	input.op in {"open_write", "write", "writeFile", "writeFileSync",
		"appendFile", "appendFileSync", "rename", "renameSync",
		"link", "linkSync", "symlink", "symlinkSync",
		"truncate", "truncateSync", "open", "openSync"}
	dotfile_match(input.path)
	r := {"action": "ask", "rule_id": "confirm-dotfile-write"}
}

dotfile_match(p) if {
	patterns := ["**/.env*", "**/.ssh/**", "**/credentials*"]
	some pat in patterns
	glob.match(pat, ["/"], p)
}

# --- http rules ---

rule_http_allowlist := r if {
	input.hook == "http"
	not host_allowed(input.host)
	r := {"action": "deny", "rule_id": "api-allowlist"}
}

host_allowed(h) if {
	h in {
		# Anthropic / Claude Code ecosystem
		"api.anthropic.com",
		"console.anthropic.com",
		"statsig.anthropic.com",
		"downloads.claude.ai",
		# MCP infrastructure
		"mcp-proxy.anthropic.com",
		"mcp.context7.com",
		# Common dev registries
		"registry.npmjs.org",
		"github.com",
		"api.github.com",
		"objects.githubusercontent.com",
		"codeload.github.com",
		# Telemetry endpoints Claude actually uses (move to a separate rule
		# if you want to flag these instead of allowing)
		"http-intake.logs.us5.datadoghq.com",
	}
}

host_allowed(h) if {
	endswith(h, ".githubusercontent.com")
}

host_allowed(h) if {
	endswith(h, ".anthropic.com")
}

# --- credential rules (Phase 2 / Stream B.2) ---
#
# The cred_use action gates `agentjail cred get <cap_id>` requests.
# Three outcomes:
#
#   allow -- the capability is in the agent's catalog AND auto_approve:true
#   ask   -- in the catalog AND auto_approve:false (B.3 owns the queue;
#            the daemon's handleCred routes ask verdicts to pending.jsonl)
#   deny  -- not in the catalog (rule_id: cred-not-granted)
#
# Data overlay: capabilities.yaml is projected by internal/capability into
# `data.agentjail.caps[agent_slug][cap_id]`. Until the overlay lands
# (next commit wires it via rego.Store), this rule reads via input
# fallback so the smoke fixtures still exercise the verdict path.
rule_cred_not_granted := r if {
	input.action == "cred_use"
	cap_id := input.resource.attr.cap_id
	agent := input.principal.attr.agent
	not data.agentjail.caps[agent][cap_id]
	r := {"action": "deny", "rule_id": "cred-not-granted",
	      "reason": sprintf("capability %s not assigned to %s", [cap_id, agent])}
}

rule_cred_auto_approve := r if {
	input.action == "cred_use"
	cap_id := input.resource.attr.cap_id
	agent := input.principal.attr.agent
	entry := data.agentjail.caps[agent][cap_id]
	entry.auto_approve == true
	r := {"action": "allow", "rule_id": "cred-auto-approve"}
}

rule_cred_ask := r if {
	input.action == "cred_use"
	cap_id := input.resource.attr.cap_id
	agent := input.principal.attr.agent
	entry := data.agentjail.caps[agent][cap_id]
	entry.auto_approve == false
	r := {"action": "ask", "rule_id": "cred-needs-approval"}
}

# --- self-tamper guard (Phase 2 / Stream B.2 codex blocker) ---
#
# Deny any file write whose path is under ~/.agentjail/** when the
# principal is bound to an agent slug (i.e. inside a wrapped session).
# Protects capabilities.yaml, pending.jsonl, active-sessions/*,
# leases.jsonl, the credstore dir, and the keychain shell-out tempfiles.
rule_self_tamper := r if {
	input.action == "write"
	input.principal.attr.agent
	input.principal.attr.agent != ""
	path := input.resource.attr.path
	startswith(path, sprintf("%s/.agentjail/", [input.context.home]))
	r := {"action": "deny", "rule_id": "self-tamper-agentjail-dir",
	      "reason": "wrapped agents may not write inside ~/.agentjail/"}
}

# --- decision ordering ---

decision := r if {
	r := rule_self_tamper
} else := r if {
	r := rule_recursive_force_in_protected_paths
} else := r if {
	r := rule_find_delete_in_home
} else := r if {
	r := rule_cred_not_granted
} else := r if {
	r := rule_cred_auto_approve
} else := r if {
	r := rule_cred_ask
} else := r if {
	r := rule_dotfile_ask
} else := r if {
	r := rule_http_allowlist
}

# --- helpers (all input-driven, WASM-portable) ---

protected_path(p) if {
	p == input.context.home
}

protected_path(p) if {
	startswith(p, sprintf("%s/", [input.context.home]))
}

protected_path(p) if {
	p == "/"
}

protected_path(p) if {
	startswith(p, "/Users/")
}
