package main

import (
	"fmt"
	"io"
	"os"
)

// runHelp is the dispatcher for "agentjail help [<topic>]".
func runHelp(args []string) int {
	if len(args) == 0 {
		printHelpTopics(os.Stdout)
		return 0
	}
	topic := args[0]
	if content, ok := helpTopics[topic]; ok {
		fmt.Fprintln(os.Stdout, content)
		return 0
	}
	fmt.Fprintf(os.Stderr, "agentjail help: unknown topic %q\n\n", topic)
	printHelpTopics(os.Stderr)
	return 2
}

// printHelpTopics writes the list of available help topics to w.
func printHelpTopics(w io.Writer) {
	fmt.Fprintln(w, "Available help topics:")
	fmt.Fprintln(w, "  mcp           MCP server and tool policy management")
	fmt.Fprintln(w, "  mcp-tools     Per-tool allow/block/ask for MCP servers")
	fmt.Fprintln(w, "  skill         Skill allow/block/ask policy management")
	fmt.Fprintln(w, "  policy        Rule-level policy management")
	fmt.Fprintln(w, "  scan          MCP server discovery and inventory")
	fmt.Fprintln(w, "  replay        Session replay and decision review")
	fmt.Fprintln(w, "  getting-started  Quick setup guide")
}

var helpTopics = map[string]string{
	"mcp": `MCP Server Policy Management
============================

agentjail controls which MCP (Model Context Protocol) servers an agent can call.

Server-level commands:
  agentjail mcp allow <server>    Add server to the allowed list
  agentjail mcp block <server>    Add server to the blocked list
  agentjail mcp list              Show server allow/block lists

Tool-level commands:
  agentjail mcp tools             List all tools per server with policy status
  agentjail mcp tools <server>    List tools for one server
  agentjail mcp tools --json      Machine-readable output
  agentjail mcp tool allow <server> <tool>   Allow a specific tool
  agentjail mcp tool block <server> <tool>   Block a specific tool
  agentjail mcp tool ask <server> <tool>     Require confirmation
  agentjail mcp tool clear <server> <tool>   Remove per-tool policy

Discovery commands:
  agentjail mcp scan              Discover servers from configs, npm, pip, Docker,
                                  audit history, and claude.ai session logs
  agentjail mcp scan --json       Machine-readable scan output
  agentjail mcp where <server>    Show which projects use a server

Policy precedence: blocked > ask > allowed > inherit (server default)

Configuration: ~/.agentjail/policy.yaml
  mcp:
    allowed:
      - "filesystem"
      - "linear-server"
    blocked:
      - "*stripe*"
    servers:
      filesystem:
        allowed_tools: ["read_file", "list_directory"]
        blocked_tools: ["delete_file"]
        ask_tools: ["write_file"]

Project-scoped policy: use --project <dir> flag on tool commands,
or place a .agentjail/policy.yaml in your project directory.`,

	"mcp-tools": `Per-Tool MCP Policy
===================

Control individual tools within an allowed MCP server.

List tools and their status:
  agentjail mcp tools                    All servers
  agentjail mcp tools chrome-devtools    One server
  agentjail mcp tools --json             JSON output

Set per-tool policy:
  agentjail mcp tool allow <server> <tool>
  agentjail mcp tool block <server> <tool>
  agentjail mcp tool ask <server> <tool>
  agentjail mcp tool clear <server> <tool>

Status values:
  inherit   No per-tool policy; uses server-level default
  allowed   Explicitly allowed (in allowed_tools list)
  blocked   Always denied (in blocked_tools list)
  ask       Requires human confirmation each time (in ask_tools list)

Project-scoped:
  agentjail mcp tool block linear-server save_issue --project ./myproject

Tool sources (how tools are discovered):
  - Audit history: tools seen in past agent sessions
  - Session logs: claude.ai remote connectors from Claude Code JSONL
  - Policy config: tools listed in allowed_tools/blocked_tools/ask_tools

Security: all mutation commands require an interactive terminal.
Agents cannot self-approve tool access.`,

	"skill": `Skill Policy Management
=======================

Control which Claude Code skills an agent can invoke.

Commands:
  agentjail skill list              Show all known skills with policy status
  agentjail skill list --json       Machine-readable output
  agentjail skill allow <skill>     Permit a specific skill
  agentjail skill block <skill>     Deny a specific skill
  agentjail skill ask <skill>       Require confirmation for a skill
  agentjail skill clear <skill>     Remove per-skill policy
  agentjail skill help              Show skill help

Skill names use colon-separated namespaces:
  superpowers:brainstorming
  posthog:error-analyzer
  deep-research
  codex-review:plan

Glob patterns are supported in policy.yaml:
  skills:
    blocked:
      - "posthog:*"          # block all posthog skills
    ask:
      - "*:brainstorming"    # confirm all brainstorming skills
    allowed:
      - "deep-research"      # explicitly allow

Default behavior: when no skill policy is configured, all skills are
allowed (backwards-compatible). Once you add entries to the blocked or
allowed lists, enforcement begins.

Policy precedence: blocked > ask > allowed > inherit

Configuration: ~/.agentjail/policy.yaml
  skills:
    allowed: []
    blocked:
      - "posthog:*"
    ask:
      - "deep-research"

Security: all mutation commands require an interactive terminal.`,

	"scan": `MCP Server Discovery
====================

agentjail mcp scan discovers all MCP servers from multiple sources:

Sources:
  1. Agent configs    Claude Code (~/.claude.json), Cursor (~/.cursor/mcp.json),
                      project .claude/settings.json
  2. Plugins          Claude Code marketplace plugins
  3. npm packages     Global npm packages matching MCP patterns
  4. pip packages     pip packages matching MCP patterns
  5. Docker           Running containers and images with "mcp" in the name
  6. Audit history    Servers seen in past agent sessions (from decisions DB)
  7. Session logs     claude.ai remote connectors from Claude Code JSONL files

Usage:
  agentjail mcp scan              Human-readable report
  agentjail mcp scan --json       Machine-readable JSON output

The scan report shows:
  - Configured Servers (from agent config files)
  - Remote Connectors (claude.ai) -- Gmail, Calendar, Drive, Typefully, etc.
  - Installed Packages (npm/pip, not yet wired into configs)
  - Docker MCP Servers
  - Audit History (servers seen in past sessions)
  - Summary counts

Remote connectors are discovered by scanning Claude Code session JSONL
files at ~/.claude/projects/*/*.jsonl for deferred_tools_delta entries.`,

	"getting-started": `Getting Started with agentjail
==============================

1. Install hooks for your coding agent:
   agentjail install                   # auto-detects Claude Code
   agentjail install --for codex       # for Codex CLI
   agentjail install --for cursor      # for Cursor

2. Check status:
   agentjail status

3. Allow MCP servers your agent needs:
   agentjail mcp allow filesystem
   agentjail mcp allow linear-server

4. View policy decisions:
   agentjail logs                      # recent decisions
   agentjail logs --action=deny        # only denials
   agentjail replay --list             # list saved sessions

5. Discover all MCP servers:
   agentjail mcp scan

6. Fine-tune per-tool policy:
   agentjail mcp tools                 # see all tools
   agentjail mcp tool block linear-server delete_comment

7. Manage skills:
   agentjail skill list                # see all skills
   agentjail skill block "posthog:*"   # block a namespace

8. Open the web UI:
   agentjail ui

Configuration: ~/.agentjail/policy.yaml
Documentation: https://agentjail.io/docs`,

	"policy": `Policy Rule Management
======================

agentjail ships with built-in policy rules that evaluate every tool call.

Commands:
  agentjail policy list             Show all rules and their status
  agentjail policy enable <rule>    Enable an optional hardening rule
  agentjail policy disable <rule>   Disable a non-locked rule

Rule categories:
  command_policy/    Shell command restrictions (sudo, rm -rf, etc.)
  file_policy/       File access controls (sensitive paths)
  mcp_policy/        MCP server and tool access
  skill_policy/      Skill invocation controls
  web_policy/        Network egress controls
  aws_policy/        AWS resource protection

Some rules are locked and cannot be disabled (security-critical).
Use 'agentjail policy list' to see which rules are locked.

Configuration: ~/.agentjail/policy.yaml
  disabled_rules:
    - "command_policy/no-curl-pipe"`,

	"replay": `Session Replay
==============

Replay and review policy decisions from saved agent sessions.

Commands:
  agentjail replay --list           List all saved sessions
  agentjail replay <session-id>     Replay a specific session
  agentjail replay --last           Replay the most recent session

The replay shows each tool call with its policy decision (allow/deny/ask),
the rule that fired, timing information, and agent glyphs.

Filtering:
  agentjail replay <id> --action=deny    Only show denied calls
  agentjail replay <id> --since=1h       Only recent decisions`,
}
