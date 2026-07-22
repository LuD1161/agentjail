package ui

import (
	"github.com/LuD1161/agentjail/internal/claudesess"
	"github.com/LuD1161/agentjail/internal/procutil"
)

// sessionNameByAncestor resolves a network session's name for rows the shield
// has not yet stamped with a claude session id: walk each live claude pid's
// ancestry looking for the owning shield pid (ADR 0100).
func sessionNameByAncestor(metas []claudesess.Meta, ownerPID int) string {
	if m, ok := claudesess.DescendantOf(metas, ownerPID); ok && procutil.Alive(m.PID) {
		return m.Name
	}
	return ""
}
