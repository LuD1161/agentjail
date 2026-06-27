// skill.go -- `agentjail skill {list,allow,block,ask,clear,help}` subcommand.
//
// This subcommand manages the skill allow/block/ask lists in
// ~/.agentjail/policy.yaml and signals the daemon to reload on each change.
// Skills are invoked as tool_name="Skill" with tool_input={"skill": "<name>"}.
//
// Usage:
//
//	agentjail skill list              -- show all known skills with policy status
//	agentjail skill list --json       -- machine-readable JSON output
//	agentjail skill allow <skill>     -- add to skills.allowed
//	agentjail skill block <skill>     -- add to skills.blocked
//	agentjail skill ask <skill>       -- add to skills.ask
//	agentjail skill clear <skill>     -- remove from all lists
//	agentjail skill help              -- show this help
//
// After each mutation, SIGHUP is sent to agentjail-daemon to reload policy.
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/ui"
	_ "modernc.org/sqlite"
)

// confirmSkillMutation gates `skill allow/block/ask/clear` behind a human at
// the keyboard. It opens /dev/tty AND reads a typed 'y' -- opening alone is
// not enough, because an agent running under a terminal-backed session inherits
// a controlling terminal and would pass an openability-only check.
// Mirrors confirmMCPMutation (mcp.go).
func confirmSkillMutation(verb, skill string) bool {
	return requireInteractiveConfirm(
		fmt.Sprintf(
			"agentjail skill %s: REFUSED -- no interactive terminal detected.\n"+
				"  Changing the skill allow/block/ask list mutates agentjail's own policy.\n"+
				"  It must be run in a terminal by a human.\n"+
				"  This restriction prevents an agent from self-approving a skill.\n", verb),
		fmt.Sprintf(
			"\n"+
				"  You are about to %s the skill %q in agentjail policy.\n"+
				"\n"+
				"  Audit:    this change is applied to ~/.agentjail/policy.yaml.\n"+
				"\n"+
				"  Type 'y' to confirm, anything else to cancel: ",
			verb, skill),
	)
}

// skillPolicyPath returns the path to policy.yaml, using projectDir if given.
// When projectDir is empty it falls back to policyConfigPath().
func skillPolicyPath(projectDir string) (string, error) {
	if projectDir != "" {
		return filepath.Join(projectDir, ".agentjail", "policy.yaml"), nil
	}
	return policyConfigPath()
}

// skillAuditDBPath returns the path to agentjail.db, derived from policyPath.
func skillAuditDBPath(policyPath string) string {
	return filepath.Join(filepath.Dir(policyPath), "agentjail.db")
}

// runSkill is the top-level dispatcher for `agentjail skill <sub>`.
// It returns an exit code so the caller can os.Exit without capturing errors.
func runSkill(args []string) int {
	if len(args) == 0 {
		printSkillUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return runSkillList(args[1:])
	case "allow":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail skill allow <skill>")
			return 2
		}
		return runSkillMutate("allow", args[1:])
	case "block":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail skill block <skill>")
			return 2
		}
		return runSkillMutate("block", args[1:])
	case "ask":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail skill ask <skill>")
			return 2
		}
		return runSkillMutate("ask", args[1:])
	case "clear":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail skill clear <skill>")
			return 2
		}
		return runSkillMutate("clear", args[1:])
	case "help", "-h", "--help":
		printSkillUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "agentjail skill: unknown subcommand %q\n", args[0])
		printSkillUsage(os.Stderr)
		return 2
	}
}

// runSkillList lists all known skills from the audit DB with their policy status.
func runSkillList(args []string) int {
	for _, a := range args {
		if a == "help" || a == "-h" || a == "--help" {
			fmt.Println("usage: agentjail skill list [--json]")
			return 0
		}
	}
	fs := flag.NewFlagSet("skill list", flag.ContinueOnError)
	jsonMode := fs.Bool("json", false, "Output JSON")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill list: %v\n", err)
		return 2
	}

	path, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill list: %v\n", err)
		return 1
	}

	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill list: load policy: %v\n", err)
		return 1
	}

	dbPath := skillAuditDBPath(path)
	skills := discoverSkillsFromDB(dbPath)

	if *jsonMode {
		return runSkillListJSON(os.Stdout, os.Stderr, skills, cfg)
	}
	return runSkillListText(os.Stdout, skills, cfg)
}

// skillEntry holds a skill name and its policy status for JSON output.
type skillEntry struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func runSkillListJSON(out, errOut io.Writer, skills []string, cfg *config.PolicyConfig) int {
	entries := make([]skillEntry, 0, len(skills))
	for _, s := range skills {
		entries = append(entries, skillEntry{
			Name:   s,
			Status: skillStatus(s, cfg),
		})
	}
	result := struct {
		Skills []skillEntry `json:"skills"`
	}{Skills: entries}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(errOut, "agentjail skill list: encode JSON: %v\n", err)
		return 1
	}
	return 0
}

func runSkillListText(out io.Writer, skills []string, cfg *config.PolicyConfig) int {
	u := ui.New(out)
	fmt.Fprintln(out, u.Section("Skills (from audit history)"))
	if len(skills) == 0 {
		fmt.Fprintln(out, "  (no skills found in audit history)")
		fmt.Fprintln(out)
		return 0
	}
	width := 0
	for _, s := range skills {
		if len(s) > width {
			width = len(s)
		}
	}
	for _, s := range skills {
		pad := strings.Repeat(" ", width-len(s)+2)
		switch skillStatus(s, cfg) {
		case "allowed":
			fmt.Fprintln(out, "  "+u.Badge("ok", s+pad+"allowed"))
		case "blocked":
			fmt.Fprintln(out, "  "+u.Badge("fail", s+pad+"blocked"))
		case "ask":
			fmt.Fprintln(out, "  "+u.Badge("warn", s+pad+"ask"))
		default:
			fmt.Fprintln(out, "  "+u.Badge("dim", "o "+s+pad+"inherit"))
		}
	}
	fmt.Fprintln(out)
	return 0
}

// runSkillMutate handles allow/block/ask/clear with optional --project flag.
func runSkillMutate(verb string, args []string) int {
	fs := flag.NewFlagSet("skill "+verb, flag.ContinueOnError)
	projectDir := fs.String("project", "", "Project directory for project-scoped policy")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill %s: %v\n", verb, err)
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintf(os.Stderr, "usage: agentjail skill %s [--project <dir>] <skill>\n", verb)
		return 2
	}
	skillName := rest[0]

	// Security gate: mutating the skill list requires an interactive human.
	if !confirmSkillMutation(verb, skillName) {
		return 1
	}

	path, err := skillPolicyPath(*projectDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill %s: %v\n", verb, err)
		return 1
	}

	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill %s: load policy: %v\n", verb, err)
		return 1
	}

	switch verb {
	case "allow":
		return runSkillAllow(skillName, path, cfg)
	case "block":
		return runSkillBlock(skillName, path, cfg)
	case "ask":
		return runSkillAsk(skillName, path, cfg)
	case "clear":
		return runSkillClear(skillName, path, cfg)
	default:
		fmt.Fprintf(os.Stderr, "agentjail skill: internal error: unknown verb %q\n", verb)
		return 1
	}
}

func runSkillAllow(skillName, path string, cfg *config.PolicyConfig) int {
	// Idempotent: already in Allowed.
	if containsString(cfg.Skills.Allowed, skillName) {
		fmt.Printf("already allowed: %s\n", skillName)
		return 0
	}
	cfg.Skills.Allowed = append(cfg.Skills.Allowed, skillName)
	cfg.Skills.Blocked = removeFromSlice(cfg.Skills.Blocked, skillName)
	cfg.Skills.Ask = removeFromSlice(cfg.Skills.Ask, skillName)
	if err := config.Save(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill allow: save policy: %v\n", err)
		return 1
	}
	fmt.Printf("allowed: %s\n", skillName)
	sighupDaemonFn()
	return 0
}

func runSkillBlock(skillName, path string, cfg *config.PolicyConfig) int {
	// Idempotent: already in Blocked.
	if containsString(cfg.Skills.Blocked, skillName) {
		fmt.Printf("already blocked: %s\n", skillName)
		return 0
	}
	cfg.Skills.Blocked = append(cfg.Skills.Blocked, skillName)
	cfg.Skills.Allowed = removeFromSlice(cfg.Skills.Allowed, skillName)
	cfg.Skills.Ask = removeFromSlice(cfg.Skills.Ask, skillName)
	if err := config.Save(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill block: save policy: %v\n", err)
		return 1
	}
	fmt.Printf("blocked: %s\n", skillName)
	sighupDaemonFn()
	return 0
}

func runSkillAsk(skillName, path string, cfg *config.PolicyConfig) int {
	// Idempotent: already in Ask.
	if containsString(cfg.Skills.Ask, skillName) {
		fmt.Printf("already ask: %s\n", skillName)
		return 0
	}
	cfg.Skills.Ask = append(cfg.Skills.Ask, skillName)
	cfg.Skills.Allowed = removeFromSlice(cfg.Skills.Allowed, skillName)
	cfg.Skills.Blocked = removeFromSlice(cfg.Skills.Blocked, skillName)
	if err := config.Save(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill ask: save policy: %v\n", err)
		return 1
	}
	fmt.Printf("ask: %s\n", skillName)
	sighupDaemonFn()
	return 0
}

func runSkillClear(skillName, path string, cfg *config.PolicyConfig) int {
	inAny := containsString(cfg.Skills.Allowed, skillName) ||
		containsString(cfg.Skills.Blocked, skillName) ||
		containsString(cfg.Skills.Ask, skillName)
	if !inAny {
		fmt.Printf("not in any list: %s\n", skillName)
		return 0
	}
	cfg.Skills.Allowed = removeFromSlice(cfg.Skills.Allowed, skillName)
	cfg.Skills.Blocked = removeFromSlice(cfg.Skills.Blocked, skillName)
	cfg.Skills.Ask = removeFromSlice(cfg.Skills.Ask, skillName)
	if err := config.Save(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail skill clear: save policy: %v\n", err)
		return 1
	}
	fmt.Printf("cleared: %s\n", skillName)
	sighupDaemonFn()
	return 0
}

// skillStatus returns the policy status of a skill name against the config.
// Precedence: blocked > ask > allowed > inherit.
func skillStatus(name string, cfg *config.PolicyConfig) string {
	if containsString(cfg.Skills.Blocked, name) {
		return "blocked"
	}
	if containsString(cfg.Skills.Ask, name) {
		return "ask"
	}
	if containsString(cfg.Skills.Allowed, name) {
		return "allowed"
	}
	return "inherit"
}

// discoverSkillsFromDB opens the audit DB read-only, queries distinct skill
// names from decisions where tool_name = 'Skill', parses the skill field from
// tool_input_redacted JSON, and returns a sorted, deduplicated list.
// Returns an empty slice (not an error) if the DB does not exist.
func discoverSkillsFromDB(dbPath string) []string {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return []string{}
	}

	// Open the DB read-only using a file URI with mode=ro.
	safeEscaped := strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23").Replace(dbPath)
	dsn := "file:" + safeEscaped + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return []string{}
	}
	defer db.Close()

	rows, err := db.Query(`SELECT DISTINCT tool_input_redacted FROM decisions WHERE tool_name = 'Skill'`)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil || !raw.Valid || raw.String == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(raw.String), &obj); err != nil {
			continue
		}
		skillVal, ok := obj["skill"]
		if !ok {
			continue
		}
		skillStr, ok := skillVal.(string)
		if !ok || skillStr == "" {
			continue
		}
		seen[skillStr] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// printSkillUsage writes the skill subcommand help to w.
func printSkillUsage(w io.Writer) {
	u := ui.New(w)
	const bodyIndent = "  "

	fmt.Fprintln(w, u.Header("agentjail skill"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Usage"))
	fmt.Fprintln(w, bodyIndent+"agentjail skill <command> [skill]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Commands"))
	cmds := []struct {
		name string
		desc string
	}{
		{"list", "Show skills from audit history with policy status"},
		{"list --json", "Output JSON array of skills with status"},
		{"allow <skill>", "Add a skill to the allowed list"},
		{"block <skill>", "Add a skill to the blocked list (and remove from allowed/ask)"},
		{"ask <skill>", "Add a skill to the ask list (require confirmation)"},
		{"clear <skill>", "Remove a skill from all lists (revert to inherited policy)"},
		{"help", "Show this help"},
	}
	for _, c := range cmds {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Flags"))
	fmt.Fprintln(w, bodyIndent+"--project <dir>    Use project-scoped policy in <dir>/.agentjail/policy.yaml")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Examples"))
	examples := []string{
		"agentjail skill list",
		"agentjail skill list --json",
		"agentjail skill allow superpowers:brainstorming",
		"agentjail skill block superpowers:using-superpowers",
		"agentjail skill ask deep-research",
		"agentjail skill clear superpowers:brainstorming",
		"agentjail skill allow --project ./myproject superpowers:brainstorming",
	}
	for _, ex := range examples {
		fmt.Fprintln(w, bodyIndent+ex)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Status values"))
	statuses := []string{
		"allowed  - skill is explicitly permitted",
		"blocked  - skill is explicitly denied",
		"ask      - skill requires human confirmation",
		"inherit  - no skill-level policy set; uses default behavior",
	}
	for _, s := range statuses {
		fmt.Fprintln(w, bodyIndent+s)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Notes"))
	notes := []string{
		"Skills are identified by their name (e.g. 'superpowers:brainstorming').",
		"After each change, agentjail-daemon is signaled to reload policy (SIGHUP).",
		"If the daemon is not running, the change takes effect on the next daemon start.",
		"Skills are discovered from the audit DB (~/.agentjail/agentjail.db).",
	}
	for _, n := range notes {
		fmt.Fprintln(w, bodyIndent+n)
	}
	fmt.Fprintln(w)
}
