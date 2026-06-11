# web_policy.rego — governance for the agent's web *read* tools.
#
# Coding agents expose two read-only web tools through the PreToolUse hook:
#   - WebSearch: a query string sent to the agent harness's own search provider.
#   - WebFetch:  an HTTP GET of a URL the agent chose, summarized back.
#
# Without a rule, both fall through to resolver/default → ask, so EVERY web
# search and fetch escalates to the user — pure noise for what is, in the common
# case, a benign read. (Worse: the agent host's per-domain "don't ask again"
# allowlist can't suppress an agentjail `ask`, so the prompt never stops.)
#
# Posture (see also the deliberate exclusion note in internal_tools.rego):
#   - WebSearch  → always allow. It is a query to the harness's search backend,
#     not an arbitrary endpoint; negligible exfil surface.
#   - WebFetch   → allow by default (read-only GET), BUT deny when the target
#     host matches a user-configured blocklist (data.agentjail.config.web.blocked,
#     glob patterns). This is domain control, not exfil-proofing: a determined
#     prompt-injected agent could still pick an unlisted host — the bigger
#     exfil hammer (Bash curl/POST) stays governed by command_policy. Users who
#     want WebFetch to prompt again can disable `web_policy/fetch` via
#     disabled_rules in policy.yaml (it falls back to resolver/default → ask).
#
# Config shape (data.agentjail.config.web, projected from ~/.agentjail/policy.yaml):
#   web:
#     blocked: ["*.internal", "169.254.*", "*tracking*"]   # host globs; default []
#
# Pattern: `candidate contains r if { ... }` partial entries; resolver.rego owns
# `decision`. An allow candidate only wins when no deny/ask fires for the same
# input, so this can never override a real block.

package agentjail

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Blocked host globs from config; default empty (nothing blocked).
web_blocked := data.agentjail.config.web.blocked if {
	data.agentjail.config.web.blocked
} else := []

# Host extracted from a WebFetch URL ("scheme://host[:port]/path" → "host"),
# lower-cased and stripped of any :port. Undefined for non-WebFetch calls or a
# malformed/scheme-less URL, which simply makes the dependent rules not fire.
web_fetch_host := host if {
	input.tool_name == "WebFetch"
	url := input.tool_input.url
	parts := split(url, "/")
	count(parts) >= 3 # ["scheme:", "", "host[:port]", ...]
	authority := parts[2]
	authority != ""
	host := lower(split(authority, ":")[0])
}

# True when the WebFetch target host matches any blocked glob. Delimiters are
# `null` (not []) so `*` spans dots — `*tracking*` matches subdomains and
# `*.internal.corp` / `169.254.*` behave as users expect for hostnames.
web_host_blocked if {
	some pattern in web_blocked
	glob.match(lower(pattern), null, web_fetch_host)
}

# ---------------------------------------------------------------------------
# Candidate rules
# ---------------------------------------------------------------------------

# WebSearch → always allow (read-only query to the harness search provider).
candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "WebSearch"
	r := {
		"action": "allow",
		"rule_id": "web_policy/search",
		"reason": "WebSearch is a read-only query to the agent's search provider",
		"impact": "read-only web search; no arbitrary endpoint",
	}
}

# WebFetch to a blocked host → deny (takes precedence over the allow below).
candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "WebFetch"
	web_host_blocked
	msg := sprintf("WebFetch host %q matches a blocked pattern in web.blocked", [web_fetch_host])
	r := {
		"action": "deny",
		"rule_id": "web_policy/fetch_blocked",
		"reason": msg,
		"impact": sprintf("would fetch from blocked host %q", [web_fetch_host]),
	}
}

# WebFetch otherwise → allow (read-only HTTP GET).
candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "WebFetch"
	not web_host_blocked
	r := {
		"action": "allow",
		"rule_id": "web_policy/fetch",
		"reason": "WebFetch is a read-only HTTP GET",
		"impact": "read-only web fetch",
	}
}
