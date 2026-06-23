package selfupdate

// SigningPubKey is the minisign public key used to verify release SHA256SUMS
// signatures. An empty string disables signature verification (dev/pre-release
// builds that have no signed manifest).
//
// Set at build time via ldflags:
//
//	-X github.com/LuD1161/agentjail/internal/selfupdate.SigningPubKey=<key>
var SigningPubKey = ""
