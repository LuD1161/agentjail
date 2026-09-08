# Legacy: sensitive-path shell-text rule

**Retired. Not loaded or installed.** See [ADR 0143-retire-path-heuristic](../adr/0143-retire-path-heuristic.md).

The sandbox already enforces configured filesystem restrictions at the actual
file operation. This old rule guessed access from shell text and blocked
harmless searches, documentation, and certificate inspection. Native file-tool
policies and other command policies remain active.

The historical implementation below is retained for reference only.

```rego
# ---------------------------------------------------------------------------
# Bash redirect / write to sensitive path. Catches commands like:
#   printf 'x' > ~/.ssh/id_rsa
#   echo y >> ~/.aws/credentials
#   tee ~/.ssh/id_rsa
#   cp foo ~/.gnupg/
# file_policy.rego catches Write/Edit/Read tool calls to these paths, but
# agents can bypass that by issuing the equivalent Bash command. This rule
# closes that loophole by denying any Bash command that operationally mentions
# a known sensitive path. Static git commit messages are inert metadata and are
# removed before matching. See ADR 0001-os-sandbox-enforcement-layer.
# ---------------------------------------------------------------------------

candidate contains r if {
	is_bash
	contains_sensitive_path(sensitive_path_scan_text(cmd))
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-bash-touch-sensitive-path",
		"reason":  "Bash access to sensitive paths is denied; use an auditable file tool if policy permits, or a purpose-built status command that does not expose contents",
		"impact":  "would touch sensitive path via Bash",
	}
}

# A literal -m/--message argument cannot access the host. Keep every other
# argument in the scan so substitutions and path-bearing options still deny.
# The message body may span lines; anchoring the prefix to a git commit command
# prevents another program's -m flag from inheriting the exemption.
# See ADR 0001-os-sandbox-enforcement-layer.
static_git_message_pattern := "(?ms)(^|\\n)(\\s*git(?:\\s+[^;&|\\n]*)?\\s+commit(?:\\s+[^;&|\\n]*)?\\s+)(-m|--message)(=|\\s+)('[^']*'|\"[^\"$`\\\\]*\")"

sensitive_path_scan_text(c) := regex.replace(
	regex.replace(c, static_git_message_pattern, "$1$2"),
	static_git_message_pattern,
	"$1$2",
)

# Sensitive path patterns - mirrors file_policy.rego's is_sensitive_path
# clauses but matches against the raw command string rather than tool_input.file_path.
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.ssh\b`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.aws\b`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.gnupg\b`, c)

contains_sensitive_path(c) if regex.match(`(/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.agentjail\b`, c)

contains_sensitive_path(c) if regex.match(`\bid_(rsa|ed25519|ecdsa|dsa)\b`, c)

contains_sensitive_path(c) if regex.match(`(^|\s|=|>|<)/etc/`, c)

# .env secret-form matches (ADR 0057): narrowed from a blanket ".env*" match
# to the secret-bearing basenames only, so bash referencing a non-secret
# TEMPLATE-named env file (.env.example, .env.docker, .env.sample, ...) is no
# longer auto-blocked - including a plain `cat` of one. This is a bounded,
# documented relaxation: file_policy's Read path still asks on the broad
# ".env*" set for the Read tool; real secret forms below stay blocked here.
# Token boundaries: a prefix delimiter class (start-of-string, whitespace,
# quote, =, /, redirect, pipe, &, ;, or open-paren) and a matching suffix
# class, so quoted/redirected/chained usages are still caught.

# bare .env
contains_sensitive_path(c) if regex.match(`(^|[\s"'=/><|&;(])\.env([\s"'>;&|)]|$)`, c)

# .env.local
contains_sensitive_path(c) if regex.match(`(^|[\s"'=/><|&;(])\.env\.local([\s"'>;&|)]|$)`, c)

# .env.<anything>.local - nested local override
contains_sensitive_path(c) if regex.match(`(^|[\s"'=/><|&;(])\.env\..+\.local([\s"'>;&|)]|$)`, c)

# known environment/secret names
contains_sensitive_path(c) if regex.match(`(^|[\s"'=/><|&;(])\.env\.(production|prod|development|dev|staging|test|qa|uat|secret|secrets|vault|override)([\s"'>;&|)]|$)`, c)

contains_sensitive_path(c) if regex.match(`\.(pem|p12|pfx|jks|keystore)\b`, c)

# ~/.npmrc - npm registry auth tokens (matches ~/, $HOME/, and absolute /Users/<u>/ forms)
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.npmrc(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.npmrc$`, c)

# ~/.pypirc - PyPI upload credentials
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.pypirc(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.pypirc$`, c)

# ~/.git-credentials - git plaintext password store
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.git-credentials(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.git-credentials$`, c)

# ~/.docker/config.json - Docker registry auth tokens
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.docker/config\.json(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.docker/config\.json$`, c)

# ~/.kube/config - Kubernetes credentials
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.kube/config(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.kube/config$`, c)

# ~/.cargo/credentials and credentials.toml - Cargo registry tokens
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.cargo/credentials(\.toml)?(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.cargo/credentials(\.toml)?$`, c)

# ~/Library/Keychains/ - macOS Keychain files
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/Library/Keychains/`, c)

```
