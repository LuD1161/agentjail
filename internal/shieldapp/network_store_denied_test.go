package shieldapp

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/mitm"
)

// The store holds decrypted bodies and the agent shares our uid, so 0600 is not
// a boundary. See ADR 0090-persist-request-bodies (D3).
func TestNetworkStoreIsReadDenied(t *testing.T) {
	denied := AgentjailReadDeniedNames()

	for _, name := range mitm.DBProtectedFileNames() {
		if !denied[name] {
			t.Errorf("%s is not read-denied: a shielded agent could read every "+
				"secret and source file from every prior session", name)
		}
	}
}

// The WAL holds uncheckpointed bodies; denying only the .db leaves the freshest
// traffic readable. See ADR 0090-persist-request-bodies (D3).
func TestNetworkStoreSidecarsAreCovered(t *testing.T) {
	denied := AgentjailReadDeniedNames()

	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		name := mitm.DBFileName + suffix
		if !denied[name] {
			t.Errorf("sidecar %s is not read-denied", name)
		}
	}
}

// Over-denial breaks observability; ~/.agentjail is otherwise agent-readable on
// purpose (AgentPaths.HomeRO).
func TestReadDenyDoesNotOverreach(t *testing.T) {
	denied := AgentjailReadDeniedNames()

	for _, name := range []string{
		"policy.yaml",
		"telemetry.json",
		"hook-fallback.json",
		"daemon.log",
		"netpacks",
	} {
		if denied[name] {
			t.Errorf("%s is read-denied but should not be", name)
		}
	}
}

// The control-plane token's denial IS the auth boundary (ADR 0067); the secrets
// set is ADR 0048. Guarded here so adding the store names cannot drop them.
func TestReadDenyKeepsPriorEntries(t *testing.T) {
	denied := AgentjailReadDeniedNames()

	for _, name := range []string{"secrets.key", "secrets"} {
		if !denied[name] {
			t.Errorf("%s dropped out of the read-deny set", name)
		}
	}
	if len(denied) <= len(mitm.DBProtectedFileNames()) {
		t.Error("read-deny set looks like it only has the store names now")
	}
}
