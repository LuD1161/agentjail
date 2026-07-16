//go:build linux

package shieldapp

import "github.com/LuD1161/agentjail/internal/netns"

// systemRootsPEM returns the host's CA roots as PEM.
//
// The path list comes from netns, which owns it because it is the same list
// InjectCA bind-mounts over: the bind-mounted store and the bundle SSL_CERT_FILE
// names must hold the same roots, and a second copy of the list would drift.
// ADR 0034-platform-backend-shared-contract.
func systemRootsPEM() ([]byte, error) {
	pem, _, err := firstReadableFile(netns.CATrustPaths())
	return pem, err
}
