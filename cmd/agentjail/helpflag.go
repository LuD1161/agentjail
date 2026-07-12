package main

import "github.com/spf13/cobra"

// wantsHelp reports whether a -h/--help flag appears among args BEFORE any "--"
// pass-through separator.
//
// Commands that set DisableFlagParsing must consult this first. With flag
// parsing disabled cobra no longer intercepts --help for them, so without this
// guard the flag falls through to the command's own arg handling and the
// command RUNS. For side-effecting commands that is a real bug — e.g.
// `agentjail uninstall --help` would perform a full uninstall, and
// `install`/`update`/`feedback --help` would install / fetch-and-replace
// binaries / transmit feedback instead of printing help.
//
// The scan stops at the first "--" so pass-through invocations still work:
// `agentjail run -- some-tool --help` forwards --help to the child tool, while
// `agentjail run --help` prints run's help.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// helpRequested prints cmd's help and returns true when a -h/--help flag was
// requested (before any "--"), so a DisableFlagParsing command's Run can
// return before doing any work:
//
//	Run: func(cmd *cobra.Command, args []string) {
//	    if helpRequested(cmd, args) {
//	        return
//	    }
//	    os.Exit(runThing(args))
//	}
func helpRequested(cmd *cobra.Command, args []string) bool {
	if wantsHelp(args) {
		_ = cmd.Help()
		return true
	}
	return false
}
