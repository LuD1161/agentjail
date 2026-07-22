package shieldapp

import (
	"os"
	"path/filepath"
)

// sessionMeta returns the label fields stamped onto every captured network
// row: the agent binary's name (e.g. "claude") and the directory the shield
// launched it from. Both ride the same every-row pattern as OwnerPID
// (ADR 0100) so the UI can render friendly session names.
func sessionMeta(agentPath string) (agent, cwd string) {
	agent = filepath.Base(agentPath)
	cwd, _ = os.Getwd()
	return agent, cwd
}
