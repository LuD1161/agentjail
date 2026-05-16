# agentjail policy library — opt-in hardening rules

This directory contains **opt-in policy rules** that are shipped with agentjail
but NOT loaded by default. Think of it as an extra package channel: rules here
are designed, tested, and ready to use, but you choose which ones fit your
threat model.

## Why opt-in?

The core policies (`file_policy.rego`, `command_policy.rego`, `mcp_policy.rego`)
are calibrated to produce zero false positives in normal development sessions.
The rules in this library go further, blocking behaviors that are *suspicious in
most contexts* but are also *legitimately used* in some workflows.

Loading every rule by default would cause too many false positives:
- Shell developers editing `~/.zshrc` would be blocked by `no-shell-init-write`.
- Homebrew formulae that patch app bundles would be blocked by `no-app-binary-write`.
- Teams using `eval $(ssh-agent -s)` would be blocked by `no-shell-eval`.

Opt-in means you pick the rules whose false-positive cost you can accept in
exchange for the extra protection they provide.

## How to enable a rule (MVP)

The MVP activation path is manual. Full CLI wiring (`agentjail policy enable`)
is coming in a future task.

**Step 1 — Copy the rule file into your active rules directory:**

```sh
cp agentpolicy/policies/library/no_shell_init_write.rego ~/.agentjail/rules/
```

Or, if you have a local agentjail checkout:

```sh
cp path/to/agentjail/agentpolicy/policies/library/no_launchctl.rego ~/.agentjail/rules/
```

**Step 2 — Reload the daemon:**

```sh
kill -HUP $(pgrep -f agentjail-daemon)
```

The daemon picks up the new rule file and hot-reloads OPA policy without
restarting the agent session.

**Step 3 — Verify the rule is active:**

```sh
agentjail status
# Should show the new rule in the loaded-rules list
```

## Rule reference

| Rule file | What it blocks | Risk if NOT enabled | False-positive risk if enabled |
|---|---|---|---|
| `no_shell_init_write.rego` | Writes to `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`, `~/.zlogout`, `~/.inputrc`, `~/.bash_login`, `~/.bash_logout` | Agent achieves persistent code execution across future shell sessions (MITRE T1546.004) | High — dotfiles setup scripts, `nvm`/`pyenv`/`homebrew` install helpers legitimately write here |
| `no_hook_self_disable.rego` | Writes to `~/.claude/settings*.json`, `~/.codex/`, `~/.cursor/`, and `~/Library/LaunchAgents/com.agentjail.*` | Agent removes its own hook, disabling all future policy enforcement | Medium — Claude Code settings, Cursor config, daemon plist are rarely edited by an agent |
| `no_app_binary_write.rego` | Writes to `/Applications/*.app/Contents/MacOS/*`, `/Applications/*.app/Contents/Frameworks/*`, and `/Applications/*.app/Contents/Resources/*.dylib` | Agent injects trojan code into an installed application binary (MITRE T1574) | Low — production code rarely modifies system app bundles; packaging scripts may |
| `no_launchctl.rego` | `launchctl submit/load/bootstrap/kickstart/enable`, `osascript` (any), `at now/+N`, `crontab -e/-r` | Agent registers an out-of-tree process that runs outside the shielded session — no hook or sandbox applies | Medium — many macOS dev workflows use `launchctl load` or `osascript` for UI automation |
| `no_history_read.rego` | Reads of `~/.zsh_history`, `~/.bash_history`, `~/.python_history`, `~/.psql_history`, `~/.lesshst`, `~/.viminfo`, Firefox/Chrome/Safari history, `~/Library/Cookies/`, `~/Library/Application Support/com.apple.sharedfilelist/` | Agent exfiltrates shell history that contains API keys, passwords, and internal hostnames | Low to medium — agents rarely have legitimate reasons to read shell or browser history |
| `no_shell_eval.rego` | `eval <expr>`, `bash -c $VAR`, `sh -c $VAR`, `$(... \| base64 -d)`, `source /dev/stdin`, `. /dev/stdin`, `<(curl ...)`, `<(wget ...)` | Agent uses obfuscation primitives to execute payloads that bypass all other pattern-matching rules | High — `eval $(ssh-agent -s)`, `eval "$(conda init bash)"`, `nvm`/`rbenv`/`pyenv` init all use eval |
| `no_daemon_kill.rego` | Commands that kill or signal `agentjail-daemon` (`kill`/`pkill`/`killall`/`launchctl bootout` targeting the daemon) | Agent shuts down the enforcement daemon, disabling all future policy checks | Low — no normal workflow kills the agentjail daemon |
| `no_destructive_git.rego` | Whole-tree destructive git: `git reset --hard`, `git clean -f` with `-d`/`-x` and no narrowing path, `git checkout -- .` / `git checkout .`, `git restore .`, `git stash clear` / `git stash drop` | Agent irrecoverably wipes uncommitted work; data loss with no remote to recover from | Medium — `reset --hard` and narrowing-path `git clean` are legitimate in some workflows. Single-file ops (`git restore README.md`) are NOT blocked |

## Architecture notes

Each rule is in `package agentjail` — the same package as the core rules.
When you copy a rule file into the active rules directory, the OPA engine merges
it with the core policies.

Library rules are designed to be **non-overlapping** with core rules: they fire
for paths and patterns that the core does not already cover. This avoids
`eval_conflict_error` when both are loaded. The core rules take precedence for
paths they explicitly handle (e.g., `~/.agentjail/` is already denied by
`file_policy/sensitive_credential`).

Run the library test suite in isolation:

```sh
opa test agentpolicy/policies/library/ -v
```

Run the core test suite to confirm library files do not affect it:

```sh
opa test agentpolicy/policies/file_policy.rego \
        agentpolicy/policies/file_policy_test.rego \
        agentpolicy/policies/mcp_policy.rego \
        agentpolicy/policies/mcp_policy_test.rego \
        agentpolicy/policies/command_policy.rego \
        agentpolicy/policies/command_policy_test.rego
```

## Forward-looking

The manual copy-and-HUP flow is the MVP. A proper CLI is planned:

```sh
# Coming in a future task
agentjail policy enable no-shell-init-write
agentjail policy list
agentjail policy disable no-shell-eval
```

This will handle rule discovery, activation, deactivation, and daemon reload
automatically.
