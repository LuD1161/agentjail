//go:build darwin

package shieldapp

// darwinRootPaths are the PEM trust stores shipped on macOS, in preference
// order. macOS keeps the authoritative roots in the System Roots keychain, not
// a file -- but the OpenSSL-family clients that read SSL_CERT_FILE
// (curl, python, git) are exactly the ones that use these PEM bundles, so this
// is the right source for the bundle those variables name.
//
// UNVERIFIED ON A MAC: written on a Linux host, so the paths and their contents
// have not been observed. The macOS tunnel is not wired at all yet (AGE-172),
// so nothing depends on this today -- it must be checked on real hardware
// before the macOS tunnel ships.
var darwinRootPaths = []string{
	"/etc/ssl/cert.pem",                  // LibreSSL/curl bundle, present on modern macOS
	"/usr/local/etc/openssl@3/cert.pem",  // Homebrew OpenSSL 3 (Intel)
	"/opt/homebrew/etc/openssl@3/cert.pem", // Homebrew OpenSSL 3 (Apple silicon)
	"/usr/local/etc/openssl/cert.pem",    // older Homebrew OpenSSL
}

// systemRootsPEM returns the host's CA roots as PEM. See darwinRootPaths for
// why a file rather than the keychain, and for the verification gap.
func systemRootsPEM() ([]byte, error) {
	pem, _, err := firstReadableFile(darwinRootPaths)
	return pem, err
}
