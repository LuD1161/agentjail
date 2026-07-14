//go:build !linux

package shieldapp

import (
	"fmt"

	"github.com/LuD1161/agentjail/internal/daemon"
)

// requestNamespace returns an error on non-Linux platforms where network
// namespaces are not available.
func requestNamespace(_, _ string) (*daemon.CreateNamespaceResp, error) {
	return nil, fmt.Errorf("network namespace tunneling requires Linux")
}

// destroyNamespace returns an error on non-Linux platforms.
func destroyNamespace(_, _ string) error {
	return fmt.Errorf("network namespace tunneling requires Linux")
}
