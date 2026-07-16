// Package redact owns the rules for deciding whether a key names something
// secret-bearing. One owner: store and mitm each kept their own list, and each
// had a hole the other covered. See ADR 0032-phantom-credentials, AGE-232.
package redact

import "strings"

// KeySubstrings are the case-insensitive substrings that mark a key as
// secret-bearing. Over-broad on purpose: a false positive costs a redacted
// value in a log, a false negative costs a leaked credential.
var KeySubstrings = []string{
	"secret", "key", "token", "password", "cred",
	"dsn", "passwd", "pw", "auth", "signature", "passphrase",
}

// KeyNames are secret-bearing keys that contain none of KeySubstrings and so
// must be named outright. Kept separate to make that reasoning visible: if a
// name here starts matching a substring, it can be deleted.
var KeyNames = []string{
	"cookie",     // and Set-Cookie, via the substring check below
	"set-cookie", // listed explicitly: "cookie" alone would not match it under
	// equality, and this list is also consulted with equality by name.
}

// ShouldRedactKey reports whether k names a value that must never be persisted
// verbatim. Matching is case-insensitive and substring-based, so vendor
// variants (dd-api-key, x-goog-api-key, anthropic-api-key) are covered without
// anyone having to enumerate them -- the enumeration is exactly what failed.
func ShouldRedactKey(k string) bool {
	lk := strings.ToLower(k)
	for _, sub := range KeySubstrings {
		if strings.Contains(lk, sub) {
			return true
		}
	}
	for _, name := range KeyNames {
		if strings.Contains(lk, name) {
			return true
		}
	}
	return false
}
