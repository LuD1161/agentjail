# AgentJail CLI Help Review

Generated from the live command tree. Paths under the home directory are sanitized as `$HOME`.

## `agentjail --help`

```text
agentjail gives every coding agent a policy guardrail -- enforcing what files
it can read/write, which MCPs it can call, and which shell commands it can run.

Usage:
  agentjail [flags]
  agentjail [command]

Examples:
  agentjail run -- codex
  agentjail stats --since 7d
  agentjail doctor

Available Commands:
  allow           Request a project host allowlist change
  completion      Generate the autocompletion script for the specified shell
  cost            Summarize agent spending across projects and models
  credential      Manage credentials for shielded sessions
  doctor          Run comprehensive protection diagnostics
  feedback        Send feedback with disclosed diagnostic metadata
  grant           Review and decide project host requests
  help            Show command help or the getting-started guide
  install         Install hooks or IDE wrappers for supported coding agents
  logs            View policy decisions
  mcp             Manage MCP server allow/block lists
  monitor         Show what policy would have blocked (monitor mode report)
  policy          Manage optional hardening rules
  replay          Replay decisions from a saved session
  run             Run a command inside the agentjail shield
  sessions        List recorded agent sessions
  skill           Manage skill allow/block/ask lists
  stats           Summarize final outcomes, policy denies, latency, and recording coverage
  status          Show a quick installed-component snapshot
  telemetry       Review and control privacy-preserving usage statistics
  trust           Manage trusted project policy overlays
  try             Check whether an action would be allowed by policy (nothing is executed)
  ui              Open the local web UI
  uninstall       Remove AgentJail components or all local AgentJail data
  update          Update agentjail binaries to the latest release
  version         Print version information

Flags:
  -h, --help       help for agentjail
      --no-color   Disable color in human-readable output

Use "agentjail [command] --help" for more information about a command.
```

## `agentjail allow --help`

```text
Request that a blocked host be added to the current project's network policy.

When policy blocks a domain that the current task needs, request it with:

  agentjail allow host <hostname>

<hostname> is a DNS name such as api.example.com, not a URL. The request does
not grant access by itself: a human must approve it from a trusted terminal.
Approval persists the host in the project's .agentjail/policy.yaml for future
sessions; it does not widen the currently running sandbox. Use --reason to tell
the approver why the project needs the host.

Usage:
  agentjail allow [command]

Examples:
  # Ask a human to add this host to the project policy.
  agentjail allow host api.example.com

  # Explain why future project sessions need the host.
  agentjail allow host api.example.com --reason "Needed for deployment checks"

Available Commands:
  host        Request that a host be added to the project network policy

Flags:
  -h, --help   help for allow

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail allow [command] --help" for more information about a command.
```

## `agentjail allow host --help`

```text
Files a grant REQUEST for host with the running agentjail daemon for the
current project. This command only files intent -- it grants nothing by itself.
A human must run 'agentjail grant list' and 'agentjail grant approve <grant_id>'
from a trusted terminal outside the sandbox. Approval writes the host into the
project overlay for future launches; the current sandbox is unchanged.

Usage:
  agentjail allow host <host> [flags]

Examples:
  # Ask a human to add this host to the project policy.
  agentjail allow host api.example.com

  # Explain why future project sessions need the host.
  agentjail allow host api.example.com --reason "Needed for deployment checks"

Flags:
  -h, --help            help for host
      --reason string   Optional justification shown to the human approver

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail completion --help`

```text
Generate the autocompletion script for agentjail for the specified shell.
See each sub-command's help for details on how to use the generated script.

Usage:
  agentjail completion [command]

Available Commands:
  bash        Generate the autocompletion script for bash
  fish        Generate the autocompletion script for fish
  zsh         Generate the autocompletion script for zsh

Flags:
  -h, --help   help for completion

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail completion [command] --help" for more information about a command.
```

## `agentjail completion bash --help`

```text
Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(agentjail completion bash)

To load completions for every new session, execute once:

#### Linux:

	agentjail completion bash > /etc/bash_completion.d/agentjail

#### macOS:

	agentjail completion bash > $(brew --prefix)/etc/bash_completion.d/agentjail

You will need to start a new shell for this setup to take effect.

Usage:
  agentjail completion bash [flags]

Flags:
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail completion fish --help`

```text
Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	agentjail completion fish | source

To load completions for every new session, execute once:

	agentjail completion fish > ~/.config/fish/completions/agentjail.fish

You will need to start a new shell for this setup to take effect.

Usage:
  agentjail completion fish [flags]

Flags:
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail completion zsh --help`

```text
Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(agentjail completion zsh)

To load completions for every new session, execute once:

#### Linux:

	agentjail completion zsh > "${fpath[1]}/_agentjail"

#### macOS:

	agentjail completion zsh > $(brew --prefix)/share/zsh/site-functions/_agentjail

You will need to start a new shell for this setup to take effect.

Usage:
  agentjail completion zsh [flags]

Flags:
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail cost --help`

```text
Summarize agent spending across projects and models

Usage:
  agentjail cost [flags]

Examples:
  agentjail cost --period 7d
  agentjail cost --period 24h --project "$PWD"
  agentjail cost --period 30d --json

Flags:
  -h, --help             help for cost
      --json             write machine-readable JSON instead of the terminal dashboard
      --period string    positive report duration up to 90d (for example: 12h, 7d, 30d) (default "7d")
      --project string   include only sessions for project directory PATH

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail credential --help`

```text
Manage static credentials in AgentJail's encrypted local broker.

Credential names are arbitrary exact identifiers. AgentJail does not infer a
provider, account, permission level, or intended command from a name or tag.

Usage:
  agentjail credential [command]

Examples:
  agentjail credential list

  # Store an arbitrary bundle under an exact user-chosen ID.
  agentjail credential set aws-read-only-cred-dev \
    --from-env AWS_ACCESS_KEY_ID --from-env AWS_SECRET_ACCESS_KEY \
    --label "Development read only" --tag aws --tag dev

  agentjail credential remove aws-read-only-cred-dev

Available Commands:
  list        List stored credential identifiers without revealing their values
  remove      Remove a credential from the encrypted broker
  set         Store a credential under an arbitrary exact name

Flags:
  -h, --help   help for credential

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail credential [command] --help" for more information about a command.
```

## `agentjail credential list --help`

```text
List the user-chosen identifiers stored in AgentJail's encrypted broker.

Credential values and metadata are never printed. Use an exact returned ID with
'agentjail run --credential ID -- <command>'.

Usage:
  agentjail credential list

Examples:
  # Print stored exact identifiers, never values.
  agentjail credential list

  # Start Codex with one exact credential selected before the sandbox starts.
  agentjail run --credential aws-read-only-cred-dev -- codex

Flags:
  -h, --help   help for list

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail credential remove --help`

```text
Remove a credential from the encrypted broker

Usage:
  agentjail credential remove <name>

Examples:
  agentjail credential remove aws-read-only-cred-dev

Flags:
  -h, --help   help for remove

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail credential set --help`

```text
Store one credential bundle in AgentJail's encrypted local broker.

<name> is an arbitrary identifier such as aws-read-only-cred-prod or
slack-channel-read-token. Names and optional labels/tags are descriptive only;
the external service still defines what the credential can do.

Use one or more --from-env NAME flags to capture current environment values.
Use --from-file ENV=PATH to expose copied content through ENV as a private
mode-0600 session file. For a single value on stdin, use --from-stdin ENV.
Credential values must never be placed directly in command arguments.

Usage:
  agentjail credential set <name> [flags]

Examples:
  # Capture any set of current environment variables.
  agentjail credential set aws-read-only-cred-dev \
    --from-env AWS_ACCESS_KEY_ID --from-env AWS_SECRET_ACCESS_KEY \
    --from-env AWS_SESSION_TOKEN --label "Development read only" --tag aws --tag dev

  # Copy a file into the private session and bind its path to KUBECONFIG.
  agentjail credential set cluster-dev --from-file KUBECONFIG=./dev.kubeconfig --tag kubernetes

  # Read one value from stdin without placing it in argv.
  printf '%s' "$SLACK_TOKEN" | agentjail credential set slack-channel-read-token --from-stdin SLACK_TOKEN --tag slack

Flags:
      --from-env stringArray    capture environment variable NAME and deliver it under the same name (repeatable)
      --from-file stringArray   copy PATH into a private session file and expose its path through ENV, as ENV=PATH (repeatable)
      --from-stdin string       read one credential value from standard input and deliver it through ENV
  -h, --help                    help for set
      --label string            optional non-secret description shown during discovery
      --tag stringArray         optional non-secret discovery tag (repeatable)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail doctor --help`

```text
Diagnose platform capabilities, daemon status, hook configuration, shield
availability, network enforcement, SSH delegation, and IDE wrappers. Use
'agentjail status' for a quick installed-component snapshot.

With --fix, repair the failures agentjail can safely repair itself, then
re-check and report the real post-repair state.

Usage:
  agentjail doctor [flags]

Examples:
  agentjail doctor
  agentjail doctor --fix

Flags:
      --fix    repair the failures doctor can safely repair (default: diagnose only)
  -h, --help   help for doctor

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail feedback --help`

```text
Send your message, AgentJail version, OS, random installation ID, and optional follow-up contact. If no message is supplied, prompt interactively.

Usage:
  agentjail feedback [message...]

Examples:
  agentjail feedback "The deny reason could be clearer"

Flags:
  -h, --help   help for feedback

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail grant --help`

```text
Review project host requests filed by shielded agents and approve or deny
them from a trusted terminal outside the sandbox. Approval persists the host
in the requesting project's policy for future sessions; it does not modify the
currently running sandbox.

Usage:
  agentjail grant [command]

Examples:
  agentjail grant list
  agentjail grant history
  agentjail grant approve 01JABC123
  agentjail grant deny 01JABC123

Available Commands:
  approve     Approve a pending grant request
  deny        Deny a pending grant request
  history     Show recent project host request decisions
  list        List pending project host requests

Flags:
  -h, --help   help for grant

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail grant [command] --help" for more information about a command.
```

## `agentjail grant approve --help`

```text
Approves the pending grant request identified by <grant_id> (see 'agentjail
grant list'). The daemon persists the host into the owning session's
.agentjail/policy.yaml overlay and re-trusts it so future sessions inherit
the grant. The currently running sandbox is unchanged; launch a new session
in that project to use the updated policy.

Usage:
  agentjail grant approve <grant_id>

Examples:
  # First list pending requests and copy the GRANT_ID to approve.
  agentjail grant list

  # Then approve that request from this trusted terminal.
  agentjail grant approve 01JABC123

Flags:
  -h, --help   help for approve

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail grant deny --help`

```text
Deny a pending grant request

Usage:
  agentjail grant deny <grant_id>

Examples:
  # First list pending requests and copy the GRANT_ID to deny.
  agentjail grant list

  # Then deny that request from this trusted terminal.
  agentjail grant deny 01JABC123

Flags:
  -h, --help   help for deny

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail grant history --help`

```text
Show the 50 most recent requested, approved, and denied host-grant events from the local SQLite audit log.

Usage:
  agentjail grant history

Flags:
  -h, --help   help for history

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail grant list --help`

```text
List requests currently pending on the running daemon across all shielded
sessions. Copy a GRANT_ID from this output, then use 'agentjail grant approve'
or 'agentjail grant deny' from this trusted terminal.

Usage:
  agentjail grant list

Flags:
  -h, --help   help for list

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail help --help`

```text
Show the same help as '<command> [subcommand] --help', or open the
'getting-started' cross-command guide. Run without arguments to show the full
command list.

Usage:
  agentjail help [command] [subcommand] [flags]

Examples:
  agentjail help getting-started
  agentjail help mcp tool
  agentjail stats --help

Flags:
  -h, --help   help for help

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail install --help`

```text
Install AgentJail for one target, every detected agent, or an optional
standalone component. --chain and --replace apply only to VS Code/Cursor IDE
wrappers. --with-path-shim and --with-apparmor are standalone setup modes when
used without --for or --all.

Usage:
  agentjail install [flags]

Examples:
  agentjail install --all
  agentjail install --for codex
  agentjail install --with-path-shim

Flags:
      --all              install all detected agents non-interactively
      --chain            with --for vscode or cursor-ide, chain an existing wrapper
      --for string       install one target: claude-code, codex, cursor, vscode, or cursor-ide
  -h, --help             help for install
      --replace          with --for vscode or cursor-ide, replace an existing wrapper
      --with-apparmor    install the Linux AppArmor user-namespace profile
      --with-path-shim   install agent launch shims in ~/.agentjail/bin
  -y, --yes              assume yes for non-interactive setup

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail logs --help`

```text
View policy decisions

Usage:
  agentjail logs [flags]

Examples:
  agentjail logs --since 2h --action deny
  agentjail logs --latest 100 --json
  agentjail logs --session 625d86f1

Flags:
      --action string    include actions LIST (comma-separated: allow,ask,deny)
      --all              with --log, include non-decision INFO lines
      --basic            disable rich terminal mode
      --db string        read decisions from SQLite database at PATH (default "$HOME/.agentjail/agentjail.db")
  -h, --help             help for logs
      --json             write normalized JSON from SQLite; with --log, pass through raw daemon lines
      --latest int       print the newest N matching decisions and exit (1-10000)
      --log string       read legacy JSONL from PATH instead of SQLite (disables --latest) (default "$HOME/.agentjail/daemon.log")
      --no-color         disable ANSI color output
      --no-follow        print existing lines and exit (no tail)
      --session string   filter by session ID substring
      --since string     include decisions from the last DURATION (for example: 10m, 2h, 24h)
      --tool string      filter by exact tool name
      --v                show input summary, reason, and session ID
```

## `agentjail mcp --help`

```text
Manage MCP server allow/block lists

Usage:
  agentjail mcp [command]

Examples:
  agentjail mcp list
  agentjail mcp scan
  agentjail mcp tool list context7

Available Commands:
  allow       Add a server to the MCP allowed list
  block       Add a server to the MCP blocked list (and remove from allowed)
  list        Show current allowed and blocked MCP servers
  scan        Discover all MCP servers: configs, npm, pip, Docker, audit, remote connectors
  tool        List and manage per-tool MCP policy
  where       Show which projects use this MCP server

Flags:
  -h, --help   help for mcp

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail mcp [command] --help" for more information about a command.
```

## `agentjail mcp allow --help`

```text
Allow an exact server name from 'agentjail mcp scan' or 'agentjail mcp list'. This mutation must run from a trusted interactive terminal.

Usage:
  agentjail mcp allow <server>

Examples:
  agentjail mcp allow context7

Flags:
  -h, --help   help for allow

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp block --help`

```text
Block an exact server name from 'agentjail mcp scan' or 'agentjail mcp list'. This mutation must run from a trusted interactive terminal.

Usage:
  agentjail mcp block <server>

Examples:
  agentjail mcp block stripe

Flags:
  -h, --help   help for block

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp list --help`

```text
Show current allowed and blocked MCP servers

Usage:
  agentjail mcp list

Flags:
  -h, --help   help for list

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp scan --help`

```text
Discover all MCP servers: configs, npm, pip, Docker, audit, remote connectors

Usage:
  agentjail mcp scan [flags]

Examples:
  agentjail mcp scan
  agentjail mcp scan --json

Flags:
  -h, --help   help for scan
      --json   output as JSON

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp tool --help`

```text
List discovered MCP tool identifiers or change their policy. Use
'agentjail mcp tool list' first to copy the exact server and tool names.
Policy mutations must run from a trusted interactive terminal.

Usage:
  agentjail mcp tool [command]

Examples:
  agentjail mcp tool list context7
  agentjail mcp tool allow context7 resolve-library-id
  agentjail mcp tool ask github create_pull_request --project "$PWD"

Available Commands:
  allow       Allow a specific tool on a server
  ask         Require confirmation for a specific tool
  block       Block a specific tool on a server
  clear       Remove per-tool policy (inherit server default)
  list        List discovered MCP tools with policy status

Flags:
  -h, --help   help for tool

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail mcp tool [command] --help" for more information about a command.
```

## `agentjail mcp tool allow --help`

```text
Allow exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail mcp tool allow <server> <tool> [flags]

Examples:
  agentjail mcp tool allow context7 resolve-library-id

Flags:
  -h, --help             help for allow
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp tool ask --help`

```text
Require confirmation for exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail mcp tool ask <server> <tool> [flags]

Examples:
  agentjail mcp tool ask github create_pull_request --project "$PWD"

Flags:
  -h, --help             help for ask
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp tool block --help`

```text
Block exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail mcp tool block <server> <tool> [flags]

Examples:
  agentjail mcp tool block github delete_repository --project "$PWD"

Flags:
  -h, --help             help for block
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp tool clear --help`

```text
Clear explicit policy for exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, inherit server policy.

Usage:
  agentjail mcp tool clear <server> <tool> [flags]

Examples:
  agentjail mcp tool clear github create_pull_request --project "$PWD"

Flags:
  -h, --help             help for clear
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp tool list --help`

```text
List MCP tools observed in audit history, session logs, or policy, optionally restricted to one server.

Usage:
  agentjail mcp tool list [server] [flags]

Examples:
  agentjail mcp tool list
  agentjail mcp tool list context7 --json

Flags:
  -h, --help   help for list
      --json   output as JSON

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail mcp where --help`

```text
Show which projects use this MCP server

Usage:
  agentjail mcp where <server> [flags]

Examples:
  agentjail mcp where context7
  agentjail mcp where context7 --json

Flags:
  -h, --help   help for where
      --json   output as JSON

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail monitor --help`

```text
Summarize decisions recorded while enforcement was in monitor mode. Rows may come from an earlier monitor-mode window even when enforcement is currently enabled.

Usage:
  agentjail monitor [flags]

Examples:
  agentjail monitor --since 24h
  agentjail monitor --since 7d --json

Flags:
      --db string       read decisions from SQLite database at PATH (default "$HOME/.agentjail/agentjail.db")
  -h, --help            help for monitor
      --json            write machine-readable JSON instead of the table
      --policy string   read enforcement mode from policy file PATH (default "$HOME/.agentjail/policy.yaml")
      --since string    report window DURATION (for example: 30m, 24h, 7d); use 0 for all time (default "24h")

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail policy --help`

```text
List, enable, disable, install, or remove core, library, and custom policy rules.

Usage:
  agentjail policy [command]

Examples:
  agentjail policy list
  agentjail policy enable no_shell_init_write

  # Core rules marked "locked" cannot be disabled; other core rules require
  # --force and interactive human confirmation.
  agentjail policy disable command_policy/no-sudo --force

Available Commands:
  add         Validate and install a custom rule file into ~/.agentjail/rules/
  disable     Disable a library rule or a user-tunable core rule
  enable      Enable a library rule or re-enable a disabled rule_id
  list        Show all rules and their status
  remove      Remove a custom rule by file stem

Flags:
  -h, --help   help for policy

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail policy [command] --help" for more information about a command.
```

## `agentjail policy add --help`

```text
Validate and install a custom rule file into ~/.agentjail/rules/

Usage:
  agentjail policy add <file.rego>

Examples:
  agentjail policy add ./my-rule.rego

Flags:
  -h, --help   help for add

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail policy disable --help`

```text
Disable a library rule by name, or suppress a known rule by rule_id.

Core does not mean locked. Most core rules are user-tunable, but disabling one
weakens AgentJail's standard security posture and therefore requires both
--force and confirmation by a human in an interactive terminal. Agents and
non-interactive scripts are refused even when they pass --force.

Locked self-protection rules can never be disabled:

  file_policy/agentjail_self
  command_policy/no-policy-mutation
  resolver/default (and all resolver/* rules)

Run 'agentjail policy list' to see whether each rule is on, off, or locked.

Usage:
  agentjail policy disable <name|rule_id> [flags]

Examples:
  # Disable an optional library rule by its file name.
  agentjail policy disable no_history_read

  # Disable a user-tunable core rule from a trusted interactive terminal.
  agentjail policy disable command_policy/no-sudo --force

Flags:
      --force   allow a non-locked core rule to be disabled after interactive human confirmation
  -h, --help    help for disable

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail policy enable --help`

```text
Enable a library rule or re-enable a disabled rule_id

Usage:
  agentjail policy enable <name|rule_id>

Examples:
  agentjail policy enable no_shell_init_write
  agentjail policy enable command_policy/no-sudo

Flags:
  -h, --help   help for enable

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail policy list --help`

```text
Show all rules and their status

Usage:
  agentjail policy list

Flags:
  -h, --help   help for list

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail policy remove --help`

```text
Remove a custom rule by file stem

Usage:
  agentjail policy remove <name>

Examples:
  agentjail policy remove my-rule

Flags:
  -h, --help   help for remove

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail replay --help`

```text
Replay recorded decisions for one session. Use 'agentjail sessions' to find and filter session IDs, then pass an exact ID or unique prefix with --session.

Usage:
  agentjail replay [flags]

Examples:
  agentjail sessions --since 24h
  agentjail replay --session 625d86f1
  agentjail replay --session 625d86f1 --follow --verbose

Flags:
      --basic            force plain text output
      --db string        read sessions from SQLite database at PATH (default "$HOME/.agentjail/agentjail.db")
      --follow           follow new decisions for the session
  -h, --help             help for replay
      --no-color         disable ANSI colors
      --session string   session ID or unique ID prefix to replay
      --verbose          include redacted tool input
```

## `agentjail run --help`

```text
Run any coding agent inside the agentjail OS-native sandbox.
The agent inherits Landlock (Linux) or Seatbelt (macOS) restrictions
that prevent access to credentials, host processes, and unrestricted network.

Use --git-ssh to delegate loaded SSH-agent identities for the session, or
--no-git-ssh to override a policy default that enables delegation. AgentJail
launch flags must appear before --; everything after -- is passed unchanged to
the child command. --no-sandbox disables OS isolation and provides only the
weaker hook-based policy layer.

Usage:
  agentjail run [flags] -- <command> [args...]

Examples:
  agentjail run -- claude
  agentjail run --verbose -- codex
  agentjail run --git-ssh -- codex
  agentjail run --credential aws-read-only-cred-dev -- claude

Flags:
      --credential stringArray   select an exact broker credential ID (repeatable)
      --git-ssh                  enable Git over SSH by delegating all loaded SSH-agent identities
  -h, --help                     help for run
      --no-git-ssh               disable policy-default Git over SSH for this launch
      --no-sandbox               disable OS isolation and use weaker hook-only enforcement
      --tunnel                   route egress through the L7 policy tunnel
      --verbose                  mirror shield diagnostics to stderr

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail sessions --help`

```text
List recorded sessions from the local SQLite event store. Use the session ID with 'agentjail replay --session ID'.

Usage:
  agentjail sessions [flags]

Examples:
  agentjail sessions --active
  agentjail sessions --since 7d --json

Flags:
      --active         show only active sessions
      --db string      read sessions from SQLite database at PATH (default "$HOME/.agentjail/agentjail.db")
  -h, --help           help for sessions
      --json           output as JSON
      --since string   include sessions from last DURATION (for example: 30m, 24h, 7d); use 0 for all time (default "24h")

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail skill --help`

```text
Review skills observed in AgentJail's audit history and manage their policy. Mutations must run from a trusted interactive terminal.

Usage:
  agentjail skill [command]

Examples:
  agentjail skill list
  agentjail skill ask --project "$PWD" deploy-production

Available Commands:
  allow       Permit a specific skill
  ask         Require confirmation for a specific skill
  block       Deny a specific skill
  clear       Remove per-skill policy (revert to inherited behavior)
  list        Show skills observed in audit history with policy status

Flags:
  -h, --help   help for skill

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail skill [command] --help" for more information about a command.
```

## `agentjail skill allow --help`

```text
Permit an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail skill allow <skill> [flags]

Examples:
  agentjail skill allow code-review
  agentjail skill allow --project "$PWD" code-review

Flags:
  -h, --help             help for allow
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail skill ask --help`

```text
Require confirmation for an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail skill ask <skill> [flags]

Examples:
  agentjail skill ask --project "$PWD" deploy-production

Flags:
  -h, --help             help for ask
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail skill block --help`

```text
Deny an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail skill block <skill> [flags]

Examples:
  agentjail skill block --project "$PWD" deploy-production

Flags:
  -h, --help             help for block
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail skill clear --help`

```text
Clear explicit policy for an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.

Usage:
  agentjail skill clear <skill> [flags]

Examples:
  agentjail skill clear --project "$PWD" deploy-production

Flags:
  -h, --help             help for clear
      --project string   apply policy only to project directory PATH (default: global)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail skill list --help`

```text
List skill names observed in recorded agent activity together with their effective policy. This does not scan installed skill files.

Usage:
  agentjail skill list [flags]

Examples:
  agentjail skill list --json

Flags:
  -h, --help   help for list
      --json   output as JSON

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail stats --help`

```text
Summarize recorded final outcomes, policy denies, latency, and recording
coverage from the local SQLite event store.

The default report includes all recorded history. Use --since to select a
recent window and --top to control the number of rows in each breakdown.

Usage:
  agentjail stats [flags]

Examples:
  agentjail stats
  agentjail stats --since 24h
  agentjail stats --since 7d --top 20
  agentjail stats --since 30d --json

Flags:
      --db string      read events from SQLite database at PATH (default "$HOME/.agentjail/agentjail.db")
  -h, --help           help for stats
      --json           write machine-readable JSON instead of the terminal report
      --since string   report window DURATION (for example: 30m, 24h, 7d); use 0 for all time (default "0")
      --top int        maximum rows in each ranked breakdown (must be at least 1) (default 10)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail status --help`

```text
Show a fast read-only summary of detected agents, installed hooks, daemon state, and policy location. Use 'agentjail doctor' for comprehensive enforcement diagnostics or repair.

Usage:
  agentjail status

Flags:
  -h, --help   help for status

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail telemetry --help`

```text
Review whether usage statistics are enabled, inspect locally queued events,
or change consent. Events use a random installation ID and do not include
source code, command arguments, file paths, credential values, or policy data.

Usage:
  agentjail telemetry
  agentjail telemetry [command]

Examples:
  agentjail telemetry status
  agentjail telemetry view
  agentjail telemetry disable

Available Commands:
  disable     Disable usage statistics
  enable      Enable privacy-preserving usage statistics
  reset       Replace the random ID and clear queued events
  status      Show telemetry consent and identifier
  view        Inspect locally queued telemetry events

Flags:
  -h, --help   help for telemetry

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail telemetry [command] --help" for more information about a command.
```

## `agentjail telemetry disable --help`

```text
Persist an opt-out so new usage events are not sent.

Usage:
  agentjail telemetry disable

Flags:
  -h, --help   help for disable

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail telemetry enable --help`

```text
Persist consent to send privacy-preserving usage statistics for this installation.

Usage:
  agentjail telemetry enable

Flags:
  -h, --help   help for enable

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail telemetry reset --help`

```text
Delete all locally queued telemetry events and replace the random installation ID. This cannot be undone.

Usage:
  agentjail telemetry reset

Flags:
  -h, --help   help for reset

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail telemetry status --help`

```text
Show whether telemetry is enabled, which setting selected that state, and the random installation ID attached to queued events.

Usage:
  agentjail telemetry status

Flags:
  -h, --help   help for status

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail telemetry view --help`

```text
Print the complete local telemetry spool as JSON so you can review what would be sent.

Usage:
  agentjail telemetry view

Flags:
  -h, --help   help for view

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail trust --help`

```text
Trust the ./.agentjail/policy.yaml overlay found at PATH (default: current
directory, searching up to the git root).

A project overlay can only WIDEN policy (add allowed hosts / MCP servers); it can
never drop the non-removable essentials, un-block a blocked MCP, or clear
disabled rules. Until you trust it, the overlay is ignored and only your global
~/.agentjail/policy.yaml applies. Editing the file after trusting it revokes
trust until you run 'agentjail trust' again.

Usage:
  agentjail trust [path]
  agentjail trust [command]

Examples:
  agentjail trust add ./services/api
  agentjail trust list

Available Commands:
  add         Trust a project policy overlay
  list        List trusted overlays and whether their content is unchanged
  remove      Remove a project policy overlay from the trust list

Flags:
  -h, --help   help for trust

Global Flags:
      --no-color   Disable color in human-readable output

Use "agentjail trust [command] --help" for more information about a command.
```

## `agentjail trust add --help`

```text
Trust the .agentjail/policy.yaml found at PATH. With no PATH, search from
the current directory up to the git root. Trust is tied to the file's content
hash, so editing the overlay requires approving it again.

Usage:
  agentjail trust add [path]

Examples:
  agentjail trust add ./services/api

Flags:
  -h, --help   help for add

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail trust list --help`

```text
List trusted overlays and whether their content is unchanged

Usage:
  agentjail trust list

Flags:
  -h, --help   help for list

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail trust remove --help`

```text
Remove the .agentjail/policy.yaml found at PATH from the trust list. With
no PATH, search from the current directory up to the git root; if the overlay
was deleted, target the conventional overlay path under the current directory.

Usage:
  agentjail trust remove [path]

Examples:
  agentjail trust remove ./services/api

Flags:
  -h, --help   help for remove

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail try --help`

```text
Evaluate an action against the live daemon without executing it. For a
one-shot check, choose exactly one of a positional command, --read, or --write.
With no action, open an interactive policy-evaluation REPL; press Ctrl-D to exit.

Usage:
  agentjail try [flags] [command...]

Examples:
  agentjail try "git push origin main"
  agentjail try --read ~/.aws/credentials
  agentjail try --write /etc/hosts
  agentjail try
  agentjail try --json "rm -rf /"

Flags:
  -h, --help           help for try
      --json           emit JSON (JSONL in interactive mode)
      --read string    evaluate a Read event on this path
      --write string   evaluate a Write event on this path

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail ui --help`

```text
Open the local web UI

Usage:
  agentjail ui [flags]

Examples:
  agentjail ui
  agentjail ui --addr 127.0.0.1:9200

Flags:
      --addr string            listen on HOST:PORT (loopback only unless --insecure-bind) (default "127.0.0.1:9101")
      --db string              path to SQLite event store (default "$HOME/.agentjail/agentjail.db")
      --edit-policy            allow policy enable/disable controls
  -h, --help                   help for ui
      --insecure-bind          allow a non-loopback bind without auth or TLS
      --log string             path to daemon log (default "$HOME/.agentjail/daemon.log")
      --trusted-host strings   allow HOST through the rebinding guard (repeatable)

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail uninstall --help`

```text
With --for, remove only one agent hook or IDE wrapper. With
--path-shim-only, remove only launch shims. With neither option, stop services,
remove every hook and wrapper, and delete ~/.agentjail, including policy,
recorded sessions, statistics, logs, trust state, and credentials.

Use --keep-credentials during a full uninstall to preserve only the encrypted
credential vault and its key.

Usage:
  agentjail uninstall [flags]

Examples:
  agentjail uninstall --for cursor
  agentjail uninstall --for vscode
  agentjail uninstall --path-shim-only
  agentjail uninstall --keep-credentials

Flags:
      --for string         remove one hook or IDE wrapper: claude-code, codex, cursor, vscode, or cursor-ide
      --force              continue teardown past recoverable failures
  -h, --help               help for uninstall
      --keep-credentials   during full uninstall, preserve the encrypted credential vault
      --path-shim-only     remove only agent launch shims

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail update --help`

```text
Update agentjail binaries to the latest release

Usage:
  agentjail update [flags]

Examples:
  agentjail update
  agentjail update --force

Flags:
      --force   reinstall the current version
  -h, --help    help for update

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail version --help`

```text
Print version information

Usage:
  agentjail version

Flags:
  -h, --help   help for version

Global Flags:
      --no-color   Disable color in human-readable output
```

## `agentjail help getting-started`

```text
Getting Started with agentjail
==============================

1. Install hooks for your coding agent:
   agentjail install                   # auto-detect supported agents
   agentjail install --for codex       # install one CLI hook
   agentjail install --for vscode      # install one IDE wrapper

2. Check protection:
   agentjail status                    # quick component snapshot
   agentjail doctor                    # comprehensive diagnostics

3. Allow MCP servers your agent needs:
   agentjail mcp scan
   agentjail mcp allow filesystem

4. Review recorded activity:
   agentjail logs --action=deny
   agentjail sessions
   agentjail replay --session <id>

5. Fine-tune MCP tool and skill policy:
   agentjail mcp tool list
   agentjail mcp tool block linear-server delete_comment
   agentjail skill list
   agentjail skill block "posthog:*"

6. Open the local web UI:
   agentjail ui

Configuration: ~/.agentjail/policy.yaml
Documentation: https://agentjail.io/docs
```
