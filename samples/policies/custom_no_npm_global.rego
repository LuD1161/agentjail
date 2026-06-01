# custom_no_npm_global.rego
#
# Block `npm install -g <anything>`, `yarn global add`, and `pnpm add -g`.
# Global installs put binaries on your PATH, often with postinstall scripts
# that run as your user — a frequent agent-foot-gun ("let me just install
# this tool for you globally").
#
# Local installs (npm install <pkg>, yarn add <pkg>, pnpm add <pkg>) are
# unaffected — they live in the project's node_modules.
#
# Pattern: uses `candidate contains r if { ... }` (partial rule set entry) so this
# rule coexists cleanly with the core policies via resolver.rego. Do NOT use
# `decision = ...` (complete rule) — that would conflict with resolver.rego's
# single complete `decision` rule.

package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name == "Bash"
    cmd := input.tool_input.command
    is_npm_global_install(cmd)
    r := {
        "action":  "deny",
        "rule_id": "samples/no-npm-global",
        "reason":  "global package install via npm/yarn/pnpm puts binaries on PATH; use a project-local install instead",
        "impact":  "would install a package globally with PATH/post-install side effects",
    }
}

is_npm_global_install(cmd) if regex.match(`\bnpm\s+(i|install|add)\b.*\s(-g|--global)\b`, cmd)

is_npm_global_install(cmd) if regex.match(`\byarn\s+global\s+add\b`, cmd)

is_npm_global_install(cmd) if regex.match(`\bpnpm\s+add\b.*\s(-g|--global)\b`, cmd)
