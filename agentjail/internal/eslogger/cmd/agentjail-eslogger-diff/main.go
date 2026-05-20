// agentjail-eslogger-diff joins a macOS eslogger JSON-Lines capture with
// an agentjail events.jsonl and emits "ES-only" exec deltas — execs the
// Endpoint Security kernel saw that the user-space agentjail capture
// did not. This is the tamper-evidence cross-check.
//
// Usage:
//
//	agentjail-eslogger-diff --es <eslogger.jsonl> --aw <events.jsonl> \
//	    [--window 200ms] [--since 2026-05-23T16:40:00Z]
//
// Output: one JSON-Lines Delta per ES-only event to stdout. Parser stats
// are printed to stderr on exit.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/LuD1161/agentjail/agentjail/internal/eslogger"
)

func main() {
	esPath := flag.String("es", "", "path to eslogger JSON-Lines capture (required)")
	awPath := flag.String("aw", "", "path to agentjail events.jsonl (required)")
	window := flag.Duration("window", 200*time.Millisecond, "half-width of the time match window")
	since := flag.String("since", "", "RFC3339 timestamp; drop events before this")
	flag.Parse()

	if *esPath == "" || *awPath == "" {
		fmt.Fprintln(os.Stderr, "usage: agentjail-eslogger-diff --es <file> --aw <file> [--window 200ms] [--since RFC3339]")
		os.Exit(2)
	}

	cfg := eslogger.Config{Window: *window}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-eslogger-diff: --since: %v\n", err)
			os.Exit(2)
		}
		cfg.Since = t
	}

	es, err := os.Open(*esPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-eslogger-diff: open --es: %v\n", err)
		os.Exit(1)
	}
	defer es.Close()
	aw, err := os.Open(*awPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-eslogger-diff: open --aw: %v\n", err)
		os.Exit(1)
	}
	defer aw.Close()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)

	esStats, awStats, err := eslogger.Diff(es, aw, cfg, func(d eslogger.Delta) error {
		return enc.Encode(&d)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-eslogger-diff: diff: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr,
		"agentjail-eslogger-diff: es {lines:%d parsed:%d skipped:%d malformed:%d} aw {lines:%d parsed:%d skipped:%d malformed:%d}\n",
		esStats.Lines, esStats.Parsed, esStats.Skipped, esStats.Malformed,
		awStats.Lines, awStats.Parsed, awStats.Skipped, awStats.Malformed,
	)
}
