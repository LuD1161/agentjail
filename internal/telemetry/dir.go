// Package telemetry implements agentjail's anonymous, opt-out usage telemetry.
// See docs/TELEMETRY.md for the data contract and docs/superpowers/specs for design.
package telemetry

import (
	"os"
	"path/filepath"
)

// Paths locates the telemetry files under a base directory (~/.agentjail).
type Paths struct{ Base string }

func (p Paths) Consent() string    { return filepath.Join(p.Base, "telemetry.json") }
func (p Paths) Spool() string      { return filepath.Join(p.Base, "telemetry-spool.jsonl") }
func (p Paths) Dropped() string    { return filepath.Join(p.Base, "telemetry-spool.dropped") }
func (p Paths) Checkpoint() string { return filepath.Join(p.Base, "telemetry-rollup.partial.json") }

func homeDir() (string, error) { return os.UserHomeDir() }

// DefaultPaths returns the telemetry paths rooted at ~/.agentjail.
func DefaultPaths() (Paths, error) {
	home, err := homeDir()
	if err != nil {
		return Paths{}, err
	}
	return Paths{Base: filepath.Join(home, ".agentjail")}, nil
}
