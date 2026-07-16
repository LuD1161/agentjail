// Package redact owns the rules for deciding whether a key names something
// secret-bearing. It exists because two packages were deciding that separately
// -- internal/store by substring, internal/mitm by an exact list of eight
// header names -- and each list had a hole the other covered:
//
//	Dd-Api-Key   substring "key" catches it; the exact list does not  -> leaked to network.db
//	Cookie       the exact list catches it; no substring matches      -> would leak from the other
//
// One owner, both callers derive. ADR 0032 (never log credential values),
// ADR 0019, ADR 0034 (drift is a bug). AGE-232.
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
