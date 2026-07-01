// Package main is agentjail-shield. This file contains the environment audit
// UI helpers (printing warnings, writing JSON output).
//
// The audit domain logic (checks, findings, types) lives in
// internal/envaudit. This file re-exports the types for backward
// compatibility within the shield binary and provides the CLI-facing
// output functions.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/LuD1161/agentjail/internal/envaudit"
)

// printAuditWarnings prints human-readable warnings to stderr.
func printAuditWarnings(result *envaudit.AuditResult) {
	for _, f := range result.Findings {
		switch f.Severity {
		case envaudit.SeverityCritical:
			fmt.Fprintf(os.Stderr, "agentjail-shield AUDIT [CRITICAL]: %s: %s\n", f.Check, f.Message)
			if f.Detail != "" {
				fmt.Fprintf(os.Stderr, "  %s\n", f.Detail)
			}
		case envaudit.SeverityWarning:
			fmt.Fprintf(os.Stderr, "agentjail-shield AUDIT [WARNING]: %s: %s\n", f.Check, f.Message)
		case envaudit.SeverityInfo:
			fmt.Fprintf(os.Stderr, "agentjail-shield AUDIT [INFO]: %s: %s\n", f.Check, f.Message)
		}
	}
}

// writeAuditJSON writes the audit result as JSON to the given path.
// If path is "-", writes to stdout.
func writeAuditJSON(result *envaudit.AuditResult, path string) error {
	var w io.Writer
	if path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
