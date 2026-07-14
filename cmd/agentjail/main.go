package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/daemonapp"
	"github.com/LuD1161/agentjail/internal/netproxyapp"
	"github.com/LuD1161/agentjail/internal/secretsapp"
	"github.com/LuD1161/agentjail/internal/shieldapp"
	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/spf13/cobra"
)

func main() {
	// Multicall dispatch: when this binary is invoked via a role symlink
	// (e.g. `agentjail-daemon`), route straight to that role's Run() before
	// any cobra parsing happens. This lets a single `agentjail` binary serve
	// as the daemon/shield/netproxy/secrets binaries too (see T3 of the
	// multicall-binary refactor). The `agentjail <role> ...` subcommand form
	// (cmd_role.go) covers the non-symlinked case.
	switch filepath.Base(os.Args[0]) {
	case "agentjail-daemon":
		os.Exit(daemonapp.Run(os.Args[1:]))
	case "agentjail-shield":
		os.Exit(shieldapp.Run(os.Args[1:]))
	case "agentjail-netproxy":
		os.Exit(netproxyapp.Run(os.Args[1:]))
	case "agentjail-secrets":
		os.Exit(secretsapp.Run(os.Args[1:]))
	}

	Execute()
}

// parseTopLevelFlags pulls long-form wrapper options out of the raw
// argument vector before the subcommand switch. Today's surface is
// minimal (no top-level flags), but the parser is preserved so future
// flags can be added without disturbing per-subcommand parsers.
func parseTopLevelFlags(in []string) (rest []string, agentSlug string) {
	rest = make([]string, 0, len(in))
	i := 0
	for i < len(in) {
		a := in[i]
		switch {
		case a == "--agent":
			if i+1 >= len(in) {
				fmt.Fprintln(os.Stderr, "agentjail: --agent requires a value")
				os.Exit(2)
			}
			agentSlug = in[i+1]
			i += 2
			continue
		case strings.HasPrefix(a, "--agent="):
			agentSlug = strings.TrimPrefix(a, "--agent=")
			i++
			continue
		}
		rest = append(rest, in[i:]...)
		return rest, agentSlug
	}
	return rest, agentSlug
}

// cmdInfo is a name/description pair used to render the command list in
// usage(). It intentionally carries no behavior -- see commandList().
type cmdInfo struct {
	name string
	desc string
}

// maintenanceCommands names the subset of top-level commands that belong in
// usage()'s "Maintenance" section rather than "Commands". This only controls
// *placement*; every registered, non-hidden command is shown somewhere --
// membership here can never cause a command to be omitted (see
// commandLists).
var maintenanceCommands = map[string]bool{
	"update":    true,
	"uninstall": true,
	"version":   true,
	"help":      true,
}

// commandLists derives the top-level command list from the live cobra
// command tree (root.Commands()) instead of a hand-maintained slice, so
// usage() can never drift out of sync with the commands that are actually
// registered (see U5: usage() previously omitted sessions/skill/trust/
// allow/grants because they were added to root.go but never mirrored here).
// Hidden commands (e.g. "statusline") are excluded. The meta "help" command
// is appended manually because cobra's SetHelpCommand does not surface it
// via root.Commands().
//
// root is passed in (rather than referencing the package-level rootCmd
// directly) to avoid a Go initialization cycle: rootCmd's own RunE closure
// calls usage(), which calls commandLists() -- a direct reference to rootCmd
// here would make rootCmd's initializer depend on itself.
func commandLists(root *cobra.Command) (cmds, maintenance []cmdInfo) {
	// cobra lazily registers its own "help" and "completion" commands inside
	// Execute() (InitDefaultHelpCmd / InitDefaultCompletionCmd), so
	// root.Commands() only contains them once Execute() has actually run
	// (e.g. real invocations, not unit tests that call usage() directly).
	// "completion" is boilerplate we don't want to surface here; "help" is
	// added explicitly below so it appears consistently either way.
	var all []cmdInfo
	for _, c := range root.Commands() {
		if c.Hidden || c.Name() == "completion" || c.Name() == "help" {
			continue
		}
		all = append(all, cmdInfo{name: c.Name(), desc: c.Short})
	}
	all = append(all, cmdInfo{name: "help", desc: "Show help (agentjail help <topic> for details)"})
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })

	for _, c := range all {
		if maintenanceCommands[c.name] {
			maintenance = append(maintenance, c)
		} else {
			cmds = append(cmds, c)
		}
	}
	return cmds, maintenance
}

// usage writes styled usage information to w and returns.
// Call with os.Stdout (exit 0) for explicit help requests, or os.Stderr
// (exit 2) for missing/unknown-command errors.
func usage(w io.Writer) {
	u := ui.New(w)
	const bodyIndent = "  "

	ver := buildinfo.Version
	if ver == "" {
		ver = "dev"
	}

	fmt.Fprintln(w, u.Header("agentjail", ver, currentGOOS))
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Usage"))
	fmt.Fprintln(w, bodyIndent+"agentjail <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Commands"))

	cmds, maintenance := commandLists(rootCmd)
	for _, c := range cmds {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Maintenance"))
	for _, c := range maintenance {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Examples"))
	examples := []string{
		"agentjail claude",
		"agentjail run -- codex --approval-mode full-auto",
		"agentjail install --all",
		"agentjail install --for vscode",
		"agentjail doctor",
		"agentjail try \"rm -rf /\"",
		"agentjail logs --action=deny --since=1h",
		"agentjail policy enable no_shell_init_write",
		"agentjail mcp allow filesystem",
	}
	for _, ex := range examples {
		fmt.Fprintln(w, bodyIndent+ex)
	}
	fmt.Fprintln(w)
}
