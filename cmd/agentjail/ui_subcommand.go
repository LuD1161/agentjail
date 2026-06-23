// ui_subcommand.go — `agentjail ui` entry point.
//
// This subcommand launches a small local web server that shows all sessions,
// their event traces, and optionally allows one-click rule enable/disable.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/LuD1161/agentjail/cmd/agentjail/ui"
)

// runUI is the entry point for `agentjail ui`. Returns an exit code.
func runUI(args []string) int {
	// Parse flags manually (no new deps).
	addr := "127.0.0.1:9101"
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
	insecureBind := false
	editPolicy := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--addr" && i+1 < len(args):
			i++
			addr = args[i]
		case len(a) > 7 && a[:7] == "--addr=":
			addr = a[7:]
		case a == "--log" && i+1 < len(args):
			i++
			logPath = args[i]
		case len(a) > 6 && a[:6] == "--log=":
			logPath = a[6:]
		case a == "--db" && i+1 < len(args):
			i++
			dbPath = args[i]
		case len(a) > 5 && a[:5] == "--db=":
			dbPath = a[5:]
		case a == "--insecure-bind":
			insecureBind = true
		case a == "--edit-policy":
			editPolicy = true
		case a == "-h" || a == "--help":
			printUIUsage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "agentjail ui: unknown flag %q\n", a)
			printUIUsage()
			return 2
		}
	}

	// Refuse non-loopback bind unless --insecure-bind is passed.
	if !ui.IsLoopback(addr) && !insecureBind {
		fmt.Fprintf(os.Stderr, "agentjail ui: refusing non-loopback bind %q\n", addr)
		fmt.Fprintln(os.Stderr, "  This tool has no auth or TLS. Use --insecure-bind to override.")
		fmt.Fprintln(os.Stderr, "  Only use --insecure-bind on a trusted network.")
		return 2
	}

	fmt.Fprintf(os.Stderr, "agentjail ui — %s\n", version)
	fmt.Fprintf(os.Stderr, "serving on http://%s\n", addr)
	fmt.Fprintln(os.Stderr, "press Ctrl-C to stop")

	store := ui.NewStore()
	srv := ui.NewServer(addr, logPath, dbPath, editPolicy, store, version)

	// Graceful shutdown on SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nagentjail ui: shutting down")
		os.Exit(0)
	}()

	if err := srv.Start(coreRuleNames, libraryRuleNames, libraryRuleContent); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail ui: %v\n", err)
		return 1
	}
	return 0
}

func printUIUsage() {
	fmt.Fprintln(os.Stderr, "usage: agentjail ui [--addr 127.0.0.1:9101] [--db PATH] [--log PATH] [--edit-policy] [--insecure-bind]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  --addr ADDR        listen address (default: 127.0.0.1:9101)")
	fmt.Fprintln(os.Stderr, "  --db PATH          path to SQLite event store (default: ~/.agentjail/agentjail.db)")
	fmt.Fprintln(os.Stderr, "  --log PATH         path to daemon.log (default: ~/.agentjail/daemon.log)")
	fmt.Fprintln(os.Stderr, "  --edit-policy      allow policy enable/disable controls (default: read-only)")
	fmt.Fprintln(os.Stderr, "  --insecure-bind    allow non-loopback bind (no auth/TLS; use with care)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NOTE: local dev tool only — NOT in the v0.1.0-alpha release")
}
