//go:build !darwin && !linux

package shieldapp

func credentialProcessAlive(int) bool {
	// Unknown platforms retain artifacts rather than risk deleting a live
	// session. See ADR 0140-generic-credentials.
	return true
}
