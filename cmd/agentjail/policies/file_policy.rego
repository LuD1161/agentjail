# Package agentjail — file access policy (macOS sensitive path deny-list)
#
# This rule evaluates Claude Code PreToolUse events for file-touching tools
# (Write, Edit, Read) against a deny-list of sensitive macOS paths.
#
# Input contract (hook-wire format, matches HookInput in engine.go):
#   input.hook_event    : "PreToolUse"
#   input.tool_name     : "Write" | "Edit" | "Read" | "Bash"
#   input.tool_input    : {file_path?, path?, old_path?, content?, ...}
#   input.session_id    : string
#   input.cwd           : string   # agent's working directory (trusted project root)
#                                    CANONICAL + ABSOLUTE (symlinks/.. resolved by daemon)
#
# Each rule contributes a candidate entry to the shared partial rule set
# `candidate` (defined via resolver.rego). The resolver picks the most
# restrictive candidate (deny > ask > allow) and produces `decision`.
#
# Path contract (enforced by daemon BEFORE calling OPA — Rego does NOT normalize):
#   - input.tool_input.file_path (and path/old_path) are CANONICAL + ABSOLUTE
#     (symlinks and .. resolved by daemon ingest).
#   - input.cwd is CANONICAL + ABSOLUTE.
#
# Sensitive-path model (two tiers):
#   is_protected_credential(p) — home-anchored stores + system dirs.  Always
#     DENY regardless of cwd.  Cannot be "inside a project" meaningfully.
#     NOTE: ~/.agentjail is NOT in this predicate — it has its own dedicated
#     rule_id (file_policy/agentjail_self) so it can never be disabled even
#     when file_policy/sensitive_credential is disabled by the user.
#   is_sensitive_basename(p)   — basename/extension patterns (.env*, secrets*,
#     *.pem, etc.).  DENY when outside cwd; ASK when inside cwd (agent was
#     granted that directory but a human beat is still warranted).
#
# Temp path model:
#   is_temp_path(p) — /tmp, /private/tmp, /var/folders/…/T/, macOS $TMPDIR.
#     Always ALLOW for Write/Edit/Read — transparent scratch space.
#     Temp paths are EXCLUDED from is_protected_credential so no deny candidate
#     is emitted (the resolver is order-independent; suppression is required).
#
# Config key for dynamic temp roots (daemon injects):
#   data.agentjail.config.file.temp_roots — array of absolute temp root paths.
#   When absent, falls back to structural patterns covering macOS defaults.
#   DAEMON AGENT: inject os.TempDir()-resolved root(s) into
#   data.agentjail.config.file.temp_roots to enable this path.
#
# Disposition rules (resolver picks most-restrictive: deny > ask > allow):
#   0. is_agentjail_self(p)                                → deny  (file_policy/agentjail_self) [LOCKED]
#   1. is_protected_credential(p)                          → deny  (file_policy/sensitive_credential)
#   2. is_sensitive_basename(p) AND in_project(p)          → ask   (file_policy/sensitive_in_project)
#   3. is_sensitive_basename(p) AND NOT in_project(p)      → deny  (file_policy/sensitive_credential)
#   4. in_project(p) AND NOT sensitive                     → allow (file_policy/project_allow)
#   5. is_temp_path(p)                                     → allow (file_policy/temp_allow)
#   6. else (Write/Edit/Read)                              → ask   (file_policy/default)
#
# Default: "ask" — unknown path escalates to human rather than silently permitting.
#
# Pattern follows Cerbos' "one resource per file" organization: all file-access
# rules live here, unit-testable in isolation, composable with the umbrella
# decision wiring in resolver.rego.
package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: extract the file path from tool input.
# Write/Edit use file_path; Read uses path; rename uses old_path.
# Only one of these is defined per call; the other two are absent.
# ---------------------------------------------------------------------------

file_path := input.tool_input.file_path if {
	input.tool_input.file_path
}

file_path := input.tool_input.path if {
	not input.tool_input.file_path
	input.tool_input.path
}

file_path := input.tool_input.old_path if {
	not input.tool_input.file_path
	not input.tool_input.path
	input.tool_input.old_path
}

# ---------------------------------------------------------------------------
# Boundary predicate: true when p is exactly input.cwd or strictly under it.
# Uses equal-or-prefix-with-slash to avoid /Users/u/proj2 matching /Users/u/proj.
# ---------------------------------------------------------------------------

in_project(p) if {
	input.cwd != ""
	p == input.cwd
}

in_project(p) if {
	input.cwd != ""
	startswith(p, concat("", [input.cwd, "/"]))
}

# ---------------------------------------------------------------------------
# Temp path predicate.
#
# Covers:
#   - /tmp and /tmp/* (and macOS /private/tmp via symlink, already canonical)
#   - /private/tmp and /private/tmp/*
#   - /var/folders/<2-seg>/T/ and /var/folders/<2-seg>/T  (macOS per-user TMPDIR)
#   - /private/var/folders/<2-seg>/T/ and /private/var/folders/<2-seg>/T
#   - Any root listed in data.agentjail.config.file.temp_roots (daemon-injected)
#
# CRITICAL: these predicates must be EXCLUSIVE of is_protected_credential so
# no deny candidate is emitted for a temp path.
# ---------------------------------------------------------------------------

is_temp_path(p) if {
	p == "/tmp"
}

is_temp_path(p) if {
	startswith(p, "/tmp/")
}

is_temp_path(p) if {
	p == "/private/tmp"
}

is_temp_path(p) if {
	startswith(p, "/private/tmp/")
}

# macOS per-user temp: /var/folders/<hash1>/<hash2>/T or /var/folders/<hash1>/<hash2>/T/...
is_temp_path(p) if {
	regex.match(`^/var/folders/[^/]+/[^/]+/T(/|$)`, p)
}

is_temp_path(p) if {
	regex.match(`^/private/var/folders/[^/]+/[^/]+/T(/|$)`, p)
}

# Daemon-injected dynamic temp roots (data.agentjail.config.file.temp_roots).
# Each entry is an absolute root path; we match equal-or-under.
is_temp_path(p) if {
	some root in data.agentjail.config.file.temp_roots
	p == root
}

is_temp_path(p) if {
	some root in data.agentjail.config.file.temp_roots
	startswith(p, concat("", [root, "/"]))
}

# ---------------------------------------------------------------------------
# agentjail self-protection predicate — ~/.agentjail/ subtree.
#
# This predicate is intentionally SEPARATE from is_protected_credential so
# that its candidate (file_policy/agentjail_self) lives in the locked_rules
# set defined in resolver.rego. A user disabling file_policy/sensitive_credential
# must NOT accidentally unlock agentjail's own config directory.
# ---------------------------------------------------------------------------

is_agentjail_self(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.agentjail(/|$)`, p)
}

# ---------------------------------------------------------------------------
# Protected credential predicate — home-anchored stores + system dirs.
# ALWAYS deny regardless of cwd. EXCLUDES temp subtrees.
# NOTE: ~/.agentjail is handled by is_agentjail_self above (NOT here).
# ---------------------------------------------------------------------------

# ~/.ssh/ — SSH private keys, known_hosts, config
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.ssh(/|$)`, p)
}

# ~/.aws/ — AWS credentials, config, session tokens
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.aws(/|$)`, p)
}

# ~/.gnupg/ — GPG private keys and trust databases
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.gnupg(/|$)`, p)
}

# ~/Desktop/ — often contains sensitive documents / credentials
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/Desktop(/|$)`, p)
}

# ~/.agentjail/ is intentionally NOT listed here — it has its own predicate
# (is_agentjail_self) and candidate (file_policy/agentjail_self). Keeping them
# separate ensures agentjail self-protection stays locked even when the user
# disables file_policy/sensitive_credential.

# ~/.config/ — application configs that may contain tokens (e.g. gh, gcloud, kubectl)
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.config(/|$)`, p)
}

# ~/.npmrc — npm registry credentials (auth tokens, passwords)
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.npmrc$`, p)
}

# ~/.pypirc — PyPI upload credentials
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.pypirc$`, p)
}

# ~/.git-credentials — git credential store (plaintext passwords)
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.git-credentials$`, p)
}

# ~/.docker/config.json — Docker registry credentials and auth tokens
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.docker/config\.json$`, p)
}

# ~/.kube/config — Kubernetes cluster credentials and access tokens
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.kube/config$`, p)
}

# ~/.cargo/credentials and credentials.toml — Cargo (Rust) registry tokens
is_protected_credential(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.cargo/credentials(\.toml)?$`, p)
}

# ~/Library/Keychains/ — macOS Keychain files (passwords, certificates)
is_protected_credential(p) if {
	regex.match(`^/Users/[^/]+/Library/Keychains(/|$)`, p)
}

# /etc/ and /private/etc/ — system configuration (macOS uses /private/etc)
is_protected_credential(p) if {
	startswith(p, "/etc/")
}

is_protected_credential(p) if {
	p == "/etc"
}

is_protected_credential(p) if {
	startswith(p, "/private/etc/")
}

is_protected_credential(p) if {
	p == "/private/etc"
}

# /var/ and /private/var/ — system state (macOS /var → /private/var symlink).
# CRITICAL: temp subtrees (/var/folders/.../T/) are EXCLUDED so no deny candidate
# is emitted for temp paths. Without this exclusion, the resolver (deny > allow)
# would pick the deny over the temp_allow.
is_protected_credential(p) if {
	startswith(p, "/var/")
	not is_temp_path(p)
}

is_protected_credential(p) if {
	p == "/var"
}

is_protected_credential(p) if {
	startswith(p, "/private/var/")
	not is_temp_path(p)
}

is_protected_credential(p) if {
	p == "/private/var"
}

# ---------------------------------------------------------------------------
# Downloads path predicate — ~/Downloads/ (downgraded from hard deny to ask).
# Fires an "ask" candidate for non-sensitive files. Sensitive files (matching
# is_sensitive_basename) still get denied via the sensitive_credential rules.
# ---------------------------------------------------------------------------

is_downloads_path(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/Downloads(/|$)`, p)
}

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_downloads_path(p)
	not is_sensitive_basename(p)
	not is_agentjail_self(p)
	msg := sprintf("file %q is in ~/Downloads — review before proceeding", [p])
	r := {
		"action":  "ask",
		"rule_id": "file_policy/downloads_review",
		"reason":  msg,
	}
}

# ---------------------------------------------------------------------------
# Sensitive basename predicate — basename/extension patterns.
# These DOWNGRADE to "ask" when inside cwd; remain "deny" when outside.
# ---------------------------------------------------------------------------

# .env, .env.local, .env.production, etc. — application secrets
is_sensitive_basename(p) if {
	regex.match(`(^|/)\.env($|\.)`, p)
}

# .envrc — direnv local secret injection
is_sensitive_basename(p) if {
	regex.match(`(^|/)\.envrc$`, p)
}

# credentials files (AWS, GCP, various tooling) — matches a basename that IS
# "credentials" or that STARTS with "credentials" followed by a separator/extension
# (credentials.json, credentials.yml, credentials_old, credentials-prod). The
# trailing class avoids matching unrelated words like "credentialsmith".
is_sensitive_basename(p) if {
	regex.match(`(^|/)\.?credentials($|[._-])`, p)
}

# secrets files — same widening (secrets.yaml, secrets.json, .secrets, secrets-prod).
is_sensitive_basename(p) if {
	regex.match(`(^|/)\.?secrets($|[._-])`, p)
}

# PEM / key / PKCS12 / JKS files — certificate private keys (case-insensitive)
is_sensitive_basename(p) if {
	regex.match(`\.(pem|key|p12|pfx|jks|keystore)$`, lower(p))
}

# .netrc — machine credentials for FTP/HTTP/curl
is_sensitive_basename(p) if {
	regex.match(`(^|/)\.netrc$`, p)
}

# SSH private key files by conventional name
is_sensitive_basename(p) if {
	regex.match(`(^|/)id_rsa$`, p)
}

is_sensitive_basename(p) if {
	regex.match(`(^|/)id_ed25519$`, p)
}

is_sensitive_basename(p) if {
	regex.match(`(^|/)id_ecdsa$`, p)
}

is_sensitive_basename(p) if {
	regex.match(`(^|/)id_dsa$`, p)
}

# ---------------------------------------------------------------------------
# Rule 0 — agentjail self-protection: always deny (LOCKED rule).
# Fires for any path under ~/.agentjail/. This rule_id is in locked_rules
# (resolver.rego) so it can NEVER be suppressed by disabled_rules — even if
# the user adds "file_policy/agentjail_self" to disabled_rules it will still
# fire. This is the primary defense against an agent editing policy.yaml.
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_agentjail_self(p)
	msg := sprintf("access to ~/.agentjail path %q is denied (agentjail self-protection; rule is permanently locked)", [p])
	impact_msg := sprintf("would access agentjail configuration path %q", [p])
	r := {
		"action":  "deny",
		"rule_id": "file_policy/agentjail_self",
		"reason":  msg,
		"impact":  impact_msg,
	}
}

# ---------------------------------------------------------------------------
# Rule 1 — Protected credential: always deny.
# Fires for is_protected_credential, regardless of cwd.
# NOTE: ~/.agentjail is NOT in is_protected_credential — it fires Rule 0.
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_protected_credential(p)
	msg := sprintf("access to sensitive path %q is denied by file policy", [p])
	impact_msg := sprintf("would access sensitive path %q", [p])
	r := {
		"action":  "deny",
		"rule_id": "file_policy/sensitive_credential",
		"reason":  msg,
		"impact":  impact_msg,
	}
}

# ---------------------------------------------------------------------------
# Rule 2 — Sensitive basename inside project: ask.
# Fires when path is in cwd AND matches a basename pattern AND is NOT a
# protected credential (which hard-denies regardless).
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_sensitive_basename(p)
	in_project(p)
	not is_protected_credential(p)
	not is_agentjail_self(p)
	msg := sprintf("sensitive-named file %q is inside the project directory — review before proceeding", [p])
	impact_msg := sprintf("would access sensitive-named file %q inside project", [p])
	r := {
		"action":  "ask",
		"rule_id": "file_policy/sensitive_in_project",
		"reason":  msg,
		"impact":  impact_msg,
	}
}

# ---------------------------------------------------------------------------
# Rule 3 — Sensitive basename outside project: deny.
# Fires when path matches a basename pattern AND is NOT in cwd AND NOT a
# protected credential (which already fires rule 1 above).
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_sensitive_basename(p)
	not in_project(p)
	not is_protected_credential(p)
	not is_agentjail_self(p)
	msg := sprintf("access to sensitive path %q outside project directory is denied by file policy", [p])
	impact_msg := sprintf("would access sensitive path %q outside project", [p])
	r := {
		"action":  "deny",
		"rule_id": "file_policy/sensitive_credential",
		"reason":  msg,
		"impact":  impact_msg,
	}
}

# ---------------------------------------------------------------------------
# Rule 4 — Path is within the agent's project directory (not sensitive).
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	in_project(p)
	not is_protected_credential(p)
	not is_sensitive_basename(p)
	not is_agentjail_self(p)
	r := {
		"action":  "allow",
		"rule_id": "file_policy/project_allow",
		"reason":  "path is within project directory",
	}
}

# ---------------------------------------------------------------------------
# Rule 5 — Temp path: allow.
# CRITICAL: temp paths must not emit a deny candidate — is_protected_credential
# already excludes temp subtrees, so no collision occurs.
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_temp_path(p)
	r := {
		"action":  "allow",
		"rule_id": "file_policy/temp_allow",
		"reason":  "path is in a temporary directory",
	}
}

# ---------------------------------------------------------------------------
# Rule 6 — Agent harness internal paths: allow.
# Claude Code stores session data, tool results, and image caches under
# ~/.claude/projects/. These are agent-internal and safe to read/write.
# ~/.claude/settings*.json is still denied by no_hook_self_disable.
# ---------------------------------------------------------------------------

is_agent_harness_path(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.claude/projects(/|$)`, p)
}

is_agent_harness_path(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.claude/image-cache(/|$)`, p)
}

is_agent_harness_path(p) if {
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.claude/todos(/|$)`, p)
}

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	p := file_path
	is_agent_harness_path(p)
	not is_agentjail_self(p)
	r := {
		"action":  "allow",
		"rule_id": "file_policy/agent_harness_allow",
		"reason":  "path is in agent harness internal directory",
	}
}

# ---------------------------------------------------------------------------
# Guarded default: ask — unknown file-tool path escalates to a human.
#
# This candidate only fires when the tool is Write, Edit, or Read AND no
# more specific rule matched (i.e., the path is neither sensitive nor inside
# cwd nor a temp path). Bash commands are intentionally excluded: they fall
# through to the command_policy default-allow candidate so benign commands
# like `git status` or `cp /tmp/x /tmp/y` never prompt the user.
#
# Safety layering:
#  - Dangerous Bash patterns  → command_policy deny/ask candidates
#  - Bash touching sensitive paths → command_policy no-bash-touch-sensitive-path
#  - File tools to ~/.agentjail/ → file_policy/agentjail_self (rule 0, LOCKED)
#  - File tools to protected cred paths → file_policy/sensitive_credential (rule 1)
#  - File tools to sensitive basename outside project → file_policy/sensitive_credential (rule 3)
#  - File tools to sensitive basename inside project → file_policy/sensitive_in_project (rule 2)
#  - File tools inside CWD → file_policy/project_allow (rule 4)
#  - File tools to temp paths → file_policy/temp_allow (rule 5)
#  - Unknown file tools → this candidate (ask)
#  - Unknown tool types → resolver/default (ask)
# ---------------------------------------------------------------------------

# file_specific_matched is true when a more-specific candidate covers the path.
file_specific_matched if {
	p := file_path
	is_agentjail_self(p)
}

file_specific_matched if {
	p := file_path
	is_protected_credential(p)
}

file_specific_matched if {
	p := file_path
	is_sensitive_basename(p)
	in_project(p)
	not is_protected_credential(p)
	not is_agentjail_self(p)
}

file_specific_matched if {
	p := file_path
	is_sensitive_basename(p)
	not in_project(p)
	not is_protected_credential(p)
	not is_agentjail_self(p)
}

file_specific_matched if {
	p := file_path
	in_project(p)
	not is_protected_credential(p)
	not is_sensitive_basename(p)
	not is_agentjail_self(p)
}

file_specific_matched if {
	p := file_path
	is_temp_path(p)
}

file_specific_matched if {
	p := file_path
	is_agent_harness_path(p)
	not is_agentjail_self(p)
}

file_specific_matched if {
	p := file_path
	is_downloads_path(p)
	not is_sensitive_basename(p)
	not is_agentjail_self(p)
}

candidate contains r if {
	input.tool_name in {"Write", "Edit", "Read"}
	not file_specific_matched
	r := {
		"action":  "ask",
		"rule_id": "file_policy/default",
		"reason":  "no file policy matched",
	}
}
