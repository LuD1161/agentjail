// default_policy_embed.go — embedded default policy YAML for `agentjail install`.
//
// default_policy.yaml is a copy of agentpolicy/default_policy.yaml baked into
// the binary at compile time via go:embed so that binary-only installs (curl | sh)
// work without a checkout of the source tree.
//
// Whenever agentpolicy/default_policy.yaml changes, update the copy at
// cmd/agentjail/default_policy.yaml to keep them in sync. The test
// TestEmbeddedDefaultPolicyMatchesSource guards against drift.
package main

import _ "embed"

//go:embed default_policy.yaml
var defaultPolicyBytes []byte

// embeddedDefaultPolicy returns the embedded default policy YAML bytes.
func embeddedDefaultPolicy() []byte {
	out := make([]byte, len(defaultPolicyBytes))
	copy(out, defaultPolicyBytes)
	return out
}
