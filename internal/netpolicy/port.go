package netpolicy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Port is a validated transport destination port used by network policy.
type Port uint16

// NewPort validates and converts an integer destination port.
func NewPort(value int) (Port, error) {
	if value < 1 || value > 65535 {
		return 0, fmt.Errorf("network port %d is outside 1..65535", value)
	}
	return Port(value), nil
}

// UnmarshalYAML rejects invalid transport ports at the policy boundary.
func (p *Port) UnmarshalYAML(node *yaml.Node) error {
	var value int
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("netpolicy: decode port: %w", err)
	}
	port, err := NewPort(value)
	if err != nil {
		return err
	}
	*p = port
	return nil
}
