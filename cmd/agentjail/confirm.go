// confirm.go — the single interactive-confirmation gate for privileged,
// self-protective agentjail actions: `policy disable`, `mcp allow/block`, and
// `update`.
//
// SECURITY: this is THE human-presence check that stops an agent from mutating
// agentjail's own configuration or binaries. It lives in one place so it can be
// audited and fixed once — a bug or bypass here is fixed for every caller at
// once, rather than risking a fix that lands in two of three near-identical
// copies. Opening /dev/tty is necessary but NOT sufficient: an agent running
// under a terminal-backed session inherits a controlling terminal, so we also
// READ a typed 'y' that the agent cannot supply.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// requireInteractiveConfirm opens /dev/tty and requires the user to type 'y'.
// It returns false (refusing) when no terminal is attached — printing refuseMsg
// to stderr — or when the typed answer is not 'y'. The refuseMsg and prompt are
// fully formatted by the caller so each action explains itself; only the tty
// mechanics (and the agent-proof read) live here.
func requireInteractiveConfirm(refuseMsg, prompt string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, refuseMsg)
		return false
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	if strings.ToLower(strings.TrimSpace(line)) != "y" {
		fmt.Fprintln(tty, "Cancelled.")
		return false
	}
	return true
}
