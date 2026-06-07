package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

// runTelemetry is the `agentjail telemetry <sub>` entry point.
func runTelemetry(args []string) int {
	p, err := telemetry.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: %v\n", err)
		return 1
	}
	return runTelemetryWith(p, os.Getenv, args, os.Stdout)
}

func runTelemetryWith(p telemetry.Paths, getenv func(string) string, args []string, out io.Writer) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		c, _ := telemetry.LoadConsent(p)
		on, src := telemetry.Resolve(c, getenv)
		state := "disabled"
		if on {
			state = "enabled"
		}
		fmt.Fprintf(out, "telemetry: %s (source: %s)\nanonymous id: %s\n", state, src, c.AnonymousID)
		return 0
	case "enable", "disable":
		c, _ := telemetry.LoadConsent(p)
		c.Enabled = sub == "enable"
		if err := telemetry.SaveConsent(p, c); err != nil {
			fmt.Fprintf(out, "telemetry: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "telemetry %sd\n", sub)
		return 0
	case "view":
		evs, _ := telemetry.NewSpool(p, 1000, 512*1024).ReadAll()
		b, _ := json.MarshalIndent(evs, "", "  ")
		fmt.Fprintln(out, string(b))
		return 0
	case "reset":
		c, _ := telemetry.LoadConsent(p)
		c.AnonymousID = telemetry.NewAnonymousID()
		_ = telemetry.SaveConsent(p, c)
		_ = telemetry.NewSpool(p, 1000, 512*1024).Truncate()
		fmt.Fprintln(out, "telemetry reset (new anonymous id, spool cleared)")
		return 0
	default:
		fmt.Fprintf(out, "usage: agentjail telemetry [status|enable|disable|view|reset]\n")
		return 2
	}
}

// featureName maps a raw subcommand to a stable enum for telemetry. Unknown
// commands collapse to "other" so we never record arbitrary argv.
func featureName(cmd string) string {
	switch cmd {
	case "install", "uninstall", "status", "version", "try", "logs", "policy", "mcp", "ui", "telemetry", "feedback":
		return cmd
	case "help", "-h", "--help":
		return "help"
	default:
		return "other"
	}
}

// recordFeatureUsed spools a feature_used event for the dispatched command.
func recordFeatureUsed(cmd string) {
	p, err := telemetry.DefaultPaths()
	if err != nil {
		return
	}
	telemetry.RecordFeature(p, os.Getenv, version, featureName(cmd), nil)
}
