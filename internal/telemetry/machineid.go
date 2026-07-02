package telemetry

import (
	"crypto/sha256"
	"fmt"

	"github.com/denisbrodbeck/machineid"
)

func stableMachineID() string {
	raw := rawMachineID()
	if raw == "" {
		return ""
	}
	h := sha256.Sum256([]byte(raw + "agentjail"))
	return fmt.Sprintf("%x", h)
}

func rawMachineID() string {
	id, err := machineid.ID()
	if err != nil {
		return ""
	}
	return id
}
