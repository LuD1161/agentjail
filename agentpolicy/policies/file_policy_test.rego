# Tests for agentpolicy/policies/file_policy.rego
#
# Runs as: opa test agentpolicy/policies/ -v --filter file_policy
#
# Test taxonomy:
#   Deny cases  — protected credentials that must be blocked unconditionally
#   Ask cases   — sensitive basenames inside project (downgraded from deny)
#   Deny cases  — sensitive basenames outside project (still deny)
#   Allow cases — paths within the project's cwd that are not sensitive
#   Allow cases — temp paths (scratch space)
#   Ask cases   — paths that match neither sensitive nor project-dir rule
#   Boundary    — edge cases: exact path match, suffix collision avoidance
#   AC tests    — plan acceptance criteria
#
# All tests use the hook-wire-format input shape (HookInput from engine.go):
#   input.hook_event  "PreToolUse"
#   input.tool_name   "Write" | "Edit" | "Read"
#   input.tool_input  {file_path?, path?, old_path?, ...}
#   input.cwd         string  (canonical + absolute — daemon normalizes)
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

deny_sensitive := "file_policy/sensitive_credential"

project_allow := "file_policy/project_allow"

file_policy_default := "file_policy/default"

sensitive_in_project := "file_policy/sensitive_in_project"

temp_allow := "file_policy/temp_allow"

# Base hook-wire event for Write tool.
write_event(fp) := {
	"hook_event": "PreToolUse",
	"tool_name": "Write",
	"tool_input": {"file_path": fp, "content": "x"},
	"session_id": "s1",
	"cwd": "/Users/dev/myproject",
}

# Base hook-wire event for Read tool (uses "path" key, not "file_path").
read_event(p) := {
	"hook_event": "PreToolUse",
	"tool_name": "Read",
	"tool_input": {"path": p},
	"session_id": "s1",
	"cwd": "/Users/dev/myproject",
}

# Base hook-wire event for Edit tool.
edit_event(fp) := {
	"hook_event": "PreToolUse",
	"tool_name": "Edit",
	"tool_input": {"file_path": fp, "old_string": "a", "new_string": "b"},
	"session_id": "s1",
	"cwd": "/Users/dev/myproject",
}

# Write event with a custom cwd.
write_event_cwd(fp, cwd) := {
	"hook_event": "PreToolUse",
	"tool_name": "Write",
	"tool_input": {"file_path": fp, "content": "x"},
	"session_id": "s1",
	"cwd": cwd,
}

# Read event with a custom cwd.
read_event_cwd(p, cwd) := {
	"hook_event": "PreToolUse",
	"tool_name": "Read",
	"tool_input": {"path": p},
	"session_id": "s1",
	"cwd": cwd,
}

# ---------------------------------------------------------------------------
# Deny: ~/.ssh/id_rsa — SSH private key (direct path) — protected credential
# ---------------------------------------------------------------------------

test_ssh_key_denied if {
	agentjail.decision.action == "deny" with input as write_event("/Users/dev/.ssh/id_rsa")
	agentjail.decision.rule_id == deny_sensitive with input as write_event("/Users/dev/.ssh/id_rsa")
}

# ---------------------------------------------------------------------------
# Deny: ~/.ssh/ directory — any file under .ssh/ is denied
# ---------------------------------------------------------------------------

test_ssh_dir_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.ssh/config")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.ssh/config")
}

# ---------------------------------------------------------------------------
# Deny: ~/.aws/credentials — AWS credential file
# ---------------------------------------------------------------------------

test_aws_creds_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.aws/credentials")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.aws/credentials")
}

# ---------------------------------------------------------------------------
# Deny: .env file in a project directory — now ASK (sensitive_in_project).
# The agent was granted cwd; .env inside cwd → ask, not deny.
# ---------------------------------------------------------------------------

test_dot_env_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/.env")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/.env")
}

# .env.local variant inside project → ask
test_dot_env_local_in_project_asks if {
	agentjail.decision.action == "ask" with input as write_event("/Users/dev/myproject/.env.local")
	agentjail.decision.rule_id == sensitive_in_project with input as write_event("/Users/dev/myproject/.env.local")
}

# ---------------------------------------------------------------------------
# Deny: .env outside project — still deny
# ---------------------------------------------------------------------------

test_dot_env_outside_project_denied if {
	agentjail.decision.action == "deny" with input as read_event_cwd("/Users/other/.env", "/Users/dev/myproject")
	agentjail.decision.rule_id == deny_sensitive with input as read_event_cwd("/Users/other/.env", "/Users/dev/myproject")
}

# ---------------------------------------------------------------------------
# Ask (AC3): sensitive basename inside project → ask
# ---------------------------------------------------------------------------

# PEM cert inside project → ask (not deny)
test_pem_file_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/server.pem")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/server.pem")
}

# .key file inside project → ask
test_key_file_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/tls.key")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/tls.key")
}

# secrets.yaml inside project → ask (AC3)
test_secrets_yaml_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/secrets.yaml")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/secrets.yaml")
}

# server.key inside project → ask (AC3)
test_server_key_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/server.key")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/server.key")
}

# .env.example inside project → ask (AC3)
test_env_example_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/.env.example")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/.env.example")
}

# ---------------------------------------------------------------------------
# Deny: ~/Downloads/
# ---------------------------------------------------------------------------

test_downloads_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/Downloads/invoice.pdf")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/Downloads/invoice.pdf")
}

# ---------------------------------------------------------------------------
# Deny: ~/.gnupg/ — GPG private keys
# ---------------------------------------------------------------------------

test_gnupg_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.gnupg/secring.gpg")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.gnupg/secring.gpg")
}

# ---------------------------------------------------------------------------
# Deny: ~/.agentjail/ — prevent self-modification (file_policy/agentjail_self,
# LOCKED rule, separate from file_policy/sensitive_credential so it cannot
# be disabled even when sensitive_credential is disabled).
# ---------------------------------------------------------------------------

agentjail_self := "file_policy/agentjail_self"

test_agentjail_dir_denied if {
	agentjail.decision.action == "deny" with input as write_event("/Users/dev/.agentjail/capabilities.yaml")
	agentjail.decision.rule_id == agentjail_self with input as write_event("/Users/dev/.agentjail/capabilities.yaml")
}

test_agentjail_policy_yaml_denied if {
	agentjail.decision.action == "deny" with input as write_event("/Users/dev/.agentjail/policy.yaml")
	agentjail.decision.rule_id == agentjail_self with input as write_event("/Users/dev/.agentjail/policy.yaml")
}

# Confirm that ~/.agentjail/ does NOT emit file_policy/sensitive_credential
# (it only emits file_policy/agentjail_self — the two must not both fire).
test_agentjail_dir_does_not_emit_sensitive_credential if {
	cands := {c | some c in agentjail.candidate; c.rule_id == "file_policy/sensitive_credential"}
	count(cands) == 0 with input as write_event("/Users/dev/.agentjail/policy.yaml")
}

# ---------------------------------------------------------------------------
# Deny: /etc/ — system configuration
# ---------------------------------------------------------------------------

test_etc_denied if {
	agentjail.decision.action == "deny" with input as read_event("/etc/passwd")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/etc/passwd")
}

test_private_etc_denied if {
	agentjail.decision.action == "deny" with input as read_event("/private/etc/hosts")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/private/etc/hosts")
}

# ---------------------------------------------------------------------------
# Deny: /var/ — system state (non-temp)
# ---------------------------------------------------------------------------

test_var_denied if {
	agentjail.decision.action == "deny" with input as read_event("/var/log/system.log")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/var/log/system.log")
}

# ---------------------------------------------------------------------------
# Ask: .envrc inside project → ask
# ---------------------------------------------------------------------------

test_envrc_in_project_asks if {
	agentjail.decision.action == "ask" with input as write_event("/Users/dev/myproject/.envrc")
	agentjail.decision.rule_id == sensitive_in_project with input as write_event("/Users/dev/myproject/.envrc")
}

# ---------------------------------------------------------------------------
# Deny: .netrc — machine credentials (outside cwd)
# ---------------------------------------------------------------------------

test_netrc_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.netrc")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.netrc")
}

# ---------------------------------------------------------------------------
# Deny: id_ed25519 — SSH private key by conventional name (in ~/.ssh/ → protected)
# ---------------------------------------------------------------------------

test_id_ed25519_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.ssh/id_ed25519")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.ssh/id_ed25519")
}

# ---------------------------------------------------------------------------
# Deny: ~/.config/ — application configs (gh auth, gcloud, kubectl)
# ---------------------------------------------------------------------------

test_config_dir_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.config/gh/hosts.yml")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.config/gh/hosts.yml")
}

# ---------------------------------------------------------------------------
# AC4: Protected credential paths ALWAYS deny, even when contrived inside cwd.
# ~/.ssh, ~/.aws, etc. can never be "inside" a project meaningfully.
# ---------------------------------------------------------------------------

test_ssh_key_denied_even_in_contrived_cwd if {
	# cwd=/Users/dev puts .ssh under it, but it's a protected credential — still deny
	agentjail.decision.action == "deny" with input as read_event_cwd("/Users/dev/.ssh/id_rsa", "/Users/dev")
	agentjail.decision.rule_id == deny_sensitive with input as read_event_cwd("/Users/dev/.ssh/id_rsa", "/Users/dev")
}

test_aws_creds_denied_even_in_contrived_cwd if {
	# cwd=/Users/dev, path /Users/dev/.aws/credentials — still deny (protected credential)
	agentjail.decision.action == "deny" with input as read_event_cwd("/Users/dev/.aws/credentials", "/Users/dev")
	agentjail.decision.rule_id == deny_sensitive with input as read_event_cwd("/Users/dev/.aws/credentials", "/Users/dev")
}

# ---------------------------------------------------------------------------
# Allow: normal project file — within cwd and not sensitive
# ---------------------------------------------------------------------------

test_project_file_allowed if {
	agentjail.decision.action == "allow" with input as write_event("/Users/dev/myproject/src/main.go")
	agentjail.decision.rule_id == project_allow with input as write_event("/Users/dev/myproject/src/main.go")
}

# ---------------------------------------------------------------------------
# Allow: project subdirectory file
# ---------------------------------------------------------------------------

test_project_subdir_allowed if {
	agentjail.decision.action == "allow" with input as edit_event("/Users/dev/myproject/internal/api/handler.go")
	agentjail.decision.rule_id == project_allow with input as edit_event("/Users/dev/myproject/internal/api/handler.go")
}

# ---------------------------------------------------------------------------
# Allow: Read of a file within cwd
# ---------------------------------------------------------------------------

test_project_read_allowed if {
	agentjail.decision.action == "allow" with input as read_event("/Users/dev/myproject/README.md")
	agentjail.decision.rule_id == project_allow with input as read_event("/Users/dev/myproject/README.md")
}

# ---------------------------------------------------------------------------
# AC1: Temp paths → allow (file_policy/temp_allow), no deny candidate.
# ---------------------------------------------------------------------------

# /tmp/x → allow
test_tmp_path_allowed if {
	agentjail.decision.action == "allow" with input as write_event("/tmp/scratch.txt")
	agentjail.decision.rule_id == temp_allow with input as write_event("/tmp/scratch.txt")
}

# /private/tmp/x → allow
test_private_tmp_path_allowed if {
	agentjail.decision.action == "allow" with input as write_event("/private/tmp/scratch.txt")
	agentjail.decision.rule_id == temp_allow with input as write_event("/private/tmp/scratch.txt")
}

# macOS per-user TMPDIR: /var/folders/.../T/... → allow
test_var_folders_tmpdir_allowed if {
	agentjail.decision.action == "allow" with input as write_event("/var/folders/ab/cd12ef/T/scratch.txt")
	agentjail.decision.rule_id == temp_allow with input as write_event("/var/folders/ab/cd12ef/T/scratch.txt")
}

# macOS per-user TMPDIR via /private/var/folders/.../T/ → allow
test_private_var_folders_tmpdir_allowed if {
	agentjail.decision.action == "allow" with input as write_event("/private/var/folders/ab/cd12ef/T/scratch.txt")
	agentjail.decision.rule_id == temp_allow with input as write_event("/private/var/folders/ab/cd12ef/T/scratch.txt")
}

# AC1 strengthened: no deny candidate emitted for temp path
test_tmp_path_no_deny_candidate if {
	deny_candidates := {c | some c in agentjail.candidate; c.action == "deny"}
	count(deny_candidates) == 0 with input as write_event("/var/folders/ab/cd12ef/T/scratch.txt")
}

test_private_var_tmpdir_no_deny_candidate if {
	deny_candidates := {c | some c in agentjail.candidate; c.action == "deny"}
	count(deny_candidates) == 0 with input as write_event("/private/var/folders/ab/cd12ef/T/scratch.txt")
}

# /tmp itself → allow
test_tmp_root_allowed if {
	agentjail.decision.action == "allow" with input as write_event("/tmp/output.bin")
	agentjail.decision.rule_id == temp_allow with input as write_event("/tmp/output.bin")
}

# ---------------------------------------------------------------------------
# Deny: /var/ non-temp (e.g. /var/log/) still denied
# ---------------------------------------------------------------------------

test_var_log_still_denied if {
	agentjail.decision.action == "deny" with input as read_event("/var/log/system.log")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/var/log/system.log")
}

# ---------------------------------------------------------------------------
# Ask (default): path outside cwd and not sensitive and not temp
# ---------------------------------------------------------------------------

test_other_user_home_asks if {
	agentjail.decision.action == "ask" with input as write_event("/Users/otherperson/projects/app/main.go")
}

# ---------------------------------------------------------------------------
# Boundary: /etcetera/ must NOT match the /etc/ deny pattern
# ---------------------------------------------------------------------------

test_etc_prefix_collision_does_not_deny if {
	# /etcetera/ is NOT /etc/ — should fall through to ask
	agentjail.decision.action != "deny" with input as write_event("/etcetera/scratch/notes.txt")
}

# ---------------------------------------------------------------------------
# Boundary: ~/Desktop/ (exact directory) denied — protected credential
# ---------------------------------------------------------------------------

test_desktop_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/Desktop/secrets.txt")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/Desktop/secrets.txt")
}

# ---------------------------------------------------------------------------
# Boundary: credentials file inside project → ask (downgraded)
# ---------------------------------------------------------------------------

test_credentials_file_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/credentials")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/credentials")
}

# ---------------------------------------------------------------------------
# AC5: Sensitive basename OUTSIDE project → deny
# ---------------------------------------------------------------------------

test_credentials_json_outside_project_denied if {
	agentjail.decision.action == "deny" with input as read_event_cwd("/Users/other/credentials.json", "/Users/dev/myproject")
	agentjail.decision.rule_id == deny_sensitive with input as read_event_cwd("/Users/other/credentials.json", "/Users/dev/myproject")
}

test_secrets_yaml_outside_project_denied if {
	agentjail.decision.action == "deny" with input as read_event_cwd("/Users/other/secrets.yaml", "/Users/dev/myproject")
	agentjail.decision.rule_id == deny_sensitive with input as read_event_cwd("/Users/other/secrets.yaml", "/Users/dev/myproject")
}

# ---------------------------------------------------------------------------
# Boundary: credentials/secrets with extension or separator (in project → ask)
# ---------------------------------------------------------------------------

test_credentials_json_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/credentials.json")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/credentials.json")
}

test_credentials_underscore_in_project_asks if {
	agentjail.decision.action == "ask" with input as write_event("/Users/dev/myproject/credentials_old")
	agentjail.decision.rule_id == sensitive_in_project with input as write_event("/Users/dev/myproject/credentials_old")
}

test_secrets_yaml_in_project_asks_boundary if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/secrets.yaml")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/secrets.yaml")
}

test_dot_secrets_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/.secrets")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/.secrets")
}

# "credentialsmith" starts with "credentials" but the next char is a letter, not
# a separator — must NOT be treated as sensitive (falls to project_allow in cwd).
test_credentialsmith_not_denied if {
	agentjail.decision.action != "deny" with input as read_event("/Users/dev/myproject/credentialsmith.go")
}

# ---------------------------------------------------------------------------
# Boundary: p12 / pfx / jks / keystore extensions inside project → ask
# ---------------------------------------------------------------------------

test_p12_file_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/client.p12")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/client.p12")
}

test_keystore_file_in_project_asks if {
	agentjail.decision.action == "ask" with input as read_event("/Users/dev/myproject/app.keystore")
	agentjail.decision.rule_id == sensitive_in_project with input as read_event("/Users/dev/myproject/app.keystore")
}

# ---------------------------------------------------------------------------
# Boundary: Edit tool also triggers deny on protected credential paths
# ---------------------------------------------------------------------------

test_edit_sensitive_denied if {
	agentjail.decision.action == "deny" with input as edit_event("/Users/dev/.aws/config")
	agentjail.decision.rule_id == deny_sensitive with input as edit_event("/Users/dev/.aws/config")
}

# ---------------------------------------------------------------------------
# Boundary: old_path (rename / move tool) falls back to file_path extractor
# A rename of an SSH key must also be caught.
# ---------------------------------------------------------------------------

test_old_path_ssh_key_denied if {
	agentjail.decision.action == "deny" with input as {
		"hook_event": "PreToolUse",
		"tool_name": "Write",
		"tool_input": {"old_path": "/Users/dev/.ssh/id_rsa"},
		"session_id": "s2",
		"cwd": "/Users/dev/myproject",
	}
}

# ---------------------------------------------------------------------------
# Task A: new credential-store paths
# ---------------------------------------------------------------------------

# POSITIVE: ~/.npmrc (home form) must be denied — protected credential
test_npmrc_home_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.npmrc")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.npmrc")
}

# POSITIVE: ~/.pypirc must be denied
test_pypirc_home_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.pypirc")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.pypirc")
}

# POSITIVE: ~/.git-credentials must be denied
test_git_credentials_home_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.git-credentials")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.git-credentials")
}

# POSITIVE: ~/.docker/config.json must be denied
test_docker_config_json_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.docker/config.json")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.docker/config.json")
}

# POSITIVE: ~/.kube/config must be denied
test_kube_config_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.kube/config")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.kube/config")
}

# POSITIVE: ~/.cargo/credentials must be denied
test_cargo_credentials_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.cargo/credentials")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.cargo/credentials")
}

# POSITIVE: ~/.cargo/credentials.toml must be denied
test_cargo_credentials_toml_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/.cargo/credentials.toml")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/.cargo/credentials.toml")
}

# POSITIVE: ~/Library/Keychains/ must be denied
test_library_keychains_denied if {
	agentjail.decision.action == "deny" with input as read_event("/Users/dev/Library/Keychains/login.keychain-db")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/Users/dev/Library/Keychains/login.keychain-db")
}

# NEGATIVE: project-local .npmrc is a sensitive_basename, inside cwd → ask (not deny)
test_project_local_npmrc_not_denied if {
	agentjail.decision.action != "deny" with input as read_event("/Users/dev/myproject/.npmrc")
}

# NEGATIVE: project-local .docker/config.json — config.json is not a sensitive basename
# pattern, so it falls to project_allow
test_project_local_docker_config_not_denied if {
	agentjail.decision.action != "deny" with input as read_event("/Users/dev/myproject/.docker/config.json")
}

# ---------------------------------------------------------------------------
# Linux home path coverage (plan 002)
# ---------------------------------------------------------------------------

test_linux_home_ssh_denied if {
	agentjail.decision.action == "deny" with input as write_event("/home/dev/.ssh/id_rsa")
	agentjail.decision.rule_id == deny_sensitive with input as write_event("/home/dev/.ssh/id_rsa")
}

test_linux_home_aws_denied if {
	agentjail.decision.action == "deny" with input as read_event("/home/dev/.aws/credentials")
	agentjail.decision.rule_id == deny_sensitive with input as read_event("/home/dev/.aws/credentials")
}

test_linux_root_ssh_denied if {
	agentjail.decision.action == "deny" with input as write_event("/root/.ssh/id_rsa")
	agentjail.decision.rule_id == deny_sensitive with input as write_event("/root/.ssh/id_rsa")
}

test_linux_home_agentjail_self if {
	agentjail.decision.action == "deny" with input as write_event("/home/dev/.agentjail/policy.yaml")
	agentjail.decision.rule_id == agentjail_self with input as write_event("/home/dev/.agentjail/policy.yaml")
}

# NEGATIVE: ~/.npmrc.bak (backup file) must NOT be denied by the npmrc rule
# (the anchored regex ends with $; .npmrc.bak has an extra suffix)
test_npmrc_bak_not_denied if {
	# .npmrc.bak is outside cwd and not sensitive → should get "ask" (not deny)
	agentjail.decision.action != "deny" with input as write_event("/Users/dev/.npmrc.bak")
}

# ---------------------------------------------------------------------------
# AC-R8: Path-boundary — /Users/u/proj2/file.txt with cwd=/Users/u/proj
# must NOT hit project_allow (raw startswith bug).
# ---------------------------------------------------------------------------

test_sibling_project_does_not_match_cwd if {
	# cwd=/Users/u/proj, path=/Users/u/proj2/file.txt
	# Without boundary check, startswith("/Users/u/proj2/file.txt", "/Users/u/proj") is true.
	# With in_project, the "/" separator check prevents this false match.
	result := agentjail.decision with input as read_event_cwd("/Users/u/proj2/file.txt", "/Users/u/proj")
	result.action != "allow"
	result.rule_id != project_allow
}

# AC-R8: Ensure no project_allow candidate emitted for sibling path
test_sibling_project_no_project_allow_candidate if {
	candidates := {c | some c in agentjail.candidate; c.rule_id == "file_policy/project_allow"}
	count(candidates) == 0 with input as read_event_cwd("/Users/u/proj2/file.txt", "/Users/u/proj")
}

# AC-R8: Sibling path falls to ask (default) — not sensitive, not in cwd, not temp
test_sibling_project_falls_to_ask if {
	agentjail.decision.action == "ask" with input as read_event_cwd("/Users/u/proj2/file.txt", "/Users/u/proj")
}

# ---------------------------------------------------------------------------
# Boundary: exact cwd match (p == cwd) should be allowed
# ---------------------------------------------------------------------------

test_exact_cwd_match_allowed if {
	agentjail.decision.action == "allow" with input as write_event_cwd("/Users/dev/myproject", "/Users/dev/myproject")
	agentjail.decision.rule_id == project_allow with input as write_event_cwd("/Users/dev/myproject", "/Users/dev/myproject")
}
