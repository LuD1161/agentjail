# Package agentjail — library rule: no-app-binary-write
#
# WHAT IT BLOCKS
# --------------
# Writes (Write, Edit, or Bash cp/mv/redirect) to macOS application bundle
# binary and native library paths:
#
#   /Applications/*.app/Contents/MacOS/*       (executable binaries)
#   /Applications/*.app/Contents/Frameworks/*  (bundled frameworks/dylibs)
#   /Applications/*.app/Contents/Resources/*.dylib  (resource-area dylibs)
#
# WHY (attack scenario)
# ----------------------
# Injecting a malicious binary into an installed application is a persistent
# privilege escalation and supply-chain attack technique (MITRE ATT&CK T1574).
# Example: replacing /Applications/Slack.app/Contents/MacOS/Slack with a
# trojanized copy that exfiltrates tokens on each launch.  Because the app
# bundle is signed, modern macOS Gatekeeper / TCC will eventually quarantine
# a tampered bundle — but only at next launch, not at write time.  This rule
# blocks the write before it happens.
#
# WHY OPT-IN (false-positive risks)
# -----------------------------------
# Legitimate use-cases that would be blocked:
#   - Homebrew post-install scripts that patch app bundles (rare, but real).
#   - Manual hot-patching of development builds.
#   - Deployment scripts that overwrite a staging app binary.
# Enable this rule in user-facing sessions where the agent should never touch
# installed applications.
#
# EXAMPLE triggering input
# -------------------------
#   {"hook_event":"PreToolUse","tool_name":"Write",
#    "tool_input":{"file_path":"/Applications/Slack.app/Contents/MacOS/Slack"},
#    "session_id":"s1","cwd":"/Users/dev/project"}
#
# HOW TO ENABLE (MVP)
#   cp agentpolicy/policies/library/no_app_binary_write.rego ~/.agentjail/rules/
#   kill -HUP $(pgrep -f agentjail-daemon)

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: extract path from Write / Edit tool_input
# ---------------------------------------------------------------------------

_lib_appbin_path := input.tool_input.file_path if {
	input.tool_input.file_path
}

_lib_appbin_path := input.tool_input.path if {
	not input.tool_input.file_path
	input.tool_input.path
}

_lib_appbin_path := input.tool_input.old_path if {
	not input.tool_input.file_path
	not input.tool_input.path
	input.tool_input.old_path
}

# App bundle binary/native-lib paths that must not be overwritten.
_is_app_binary(p) if {
	# /Applications/<name>.app/Contents/MacOS/<binary>
	regex.match(`^/Applications/[^/]+\.app/Contents/MacOS/`, p)
}

_is_app_binary(p) if {
	# /Applications/<name>.app/Contents/Frameworks/ — bundled dylibs
	regex.match(`^/Applications/[^/]+\.app/Contents/Frameworks/`, p)
}

_is_app_binary(p) if {
	# /Applications/<name>.app/Contents/Resources/*.dylib
	regex.match(`^/Applications/[^/]+\.app/Contents/Resources/[^/]+\.dylib$`, p)
}

# ---------------------------------------------------------------------------
# Candidate: deny Write / Edit to app binary paths
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit"}
	p := _lib_appbin_path
	_is_app_binary(p)
	msg := sprintf("write to application binary path %q is denied (library/no-app-binary-write); trojan injection risk", [p])
	r := {
		"action":  "deny",
		"rule_id": "library/no-app-binary-write",
		"reason":  msg,
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny Bash cp/mv/redirect targeting app binary paths
# ---------------------------------------------------------------------------

candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
	c := input.tool_input.command
	regex.match(`/Applications/[^/\s'"]+\.app/Contents/(MacOS|Frameworks)/`, c)
	r := {
		"action":  "deny",
		"rule_id": "library/no-app-binary-write",
		"reason":  "Bash command targets an application bundle binary path (library/no-app-binary-write); trojan injection risk",
	}
}
