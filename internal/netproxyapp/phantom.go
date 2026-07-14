// phantom.go implements the phantom token registry -- the core data structure
// that maps opaque, agent-facing "phantom" tokens to real credentials and their
// per-host/method/path access policies.
//
// A phantom token is a random 256-bit value prefixed with "ajp_" and encoded
// in base64url (no padding).  The agent sees only phantom tokens in its env;
// the real credential never leaves the proxy process.
//
// The TLS proxy (future) will call Lookup on every outbound request, swap the
// phantom for the real credential, and enforce host/method/path restrictions
// via ValidateRequest before injecting the real secret into the upstream
// request.
//
// Thread safety: all exported methods are safe for concurrent use.
package netproxyapp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
)

// phantomEntropyBytes is the number of random bytes in a phantom token (256-bit).
const phantomEntropyBytes = 32

// phantomPrefix is prepended to every generated phantom token.
const phantomPrefix = "ajp_"

// InjectionConfig describes how the real credential is injected into the
// upstream HTTP request when the phantom token is swapped.
type InjectionConfig struct {
	// Type is one of "bearer_header", "header", or "query_parameter".
	Type string

	// Header is the HTTP header name, e.g. "Authorization" or "X-Api-Key".
	// Used when Type is "bearer_header" or "header".
	Header string

	// Scheme is the auth scheme prefix, e.g. "Bearer" or "token".
	// Used when Type is "bearer_header".  Empty for plain headers.
	Scheme string
}

// PhantomEntry binds a phantom token to a real credential and its access policy.
type PhantomEntry struct {
	// CredentialID is a human-readable name, e.g. "github", "anthropic".
	CredentialID string

	// Phantom is the opaque token the agent sees (ajp_<base64url>).
	Phantom string

	// EnvVar is the environment variable name the agent reads, e.g. "GITHUB_TOKEN".
	EnvVar string

	// AllowedHosts restricts which destination hosts may receive the real
	// credential.  Empty means all hosts are allowed.
	AllowedHosts []string

	// AllowedMethods restricts which HTTP methods may carry the real credential.
	// Empty means all methods are allowed.
	AllowedMethods []string

	// AllowedPaths restricts which request paths may carry the real credential.
	// Entries are matched as glob patterns via path.Match.
	// Empty means all paths are allowed.
	AllowedPaths []string

	// Injection describes how the real credential is placed into the upstream
	// request (header, bearer, query parameter).
	Injection InjectionConfig

	// Violation is the enforcement action when a request violates the access
	// policy: "block", "block-and-log", or "terminate".
	Violation string
}

// PhantomRegistry is a thread-safe lookup table mapping phantom tokens and env
// var names to their PhantomEntry.  It is populated at session start when the
// daemon reads credential configs and generates phantom tokens.
type PhantomRegistry struct {
	mu      sync.RWMutex
	entries map[string]*PhantomEntry // phantom token -> entry
	byEnv   map[string]*PhantomEntry // env var name -> entry
}

// NewPhantomRegistry returns an empty, ready-to-use registry.
func NewPhantomRegistry() *PhantomRegistry {
	return &PhantomRegistry{
		entries: make(map[string]*PhantomEntry),
		byEnv:   make(map[string]*PhantomEntry),
	}
}

// Register adds an entry to the registry.  It returns an error if the phantom
// token or env var name collides with an existing entry.
func (r *PhantomRegistry) Register(entry *PhantomEntry) error {
	if entry == nil {
		return errors.New("phantom: nil entry")
	}
	if entry.Phantom == "" {
		return errors.New("phantom: empty phantom token")
	}
	if entry.EnvVar == "" {
		return errors.New("phantom: empty env var")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[entry.Phantom]; exists {
		return fmt.Errorf("phantom: token collision for credential %q", entry.CredentialID)
	}
	if _, exists := r.byEnv[entry.EnvVar]; exists {
		return fmt.Errorf("phantom: env var %q already registered", entry.EnvVar)
	}

	r.entries[entry.Phantom] = entry
	r.byEnv[entry.EnvVar] = entry
	return nil
}

// Lookup finds an entry by its phantom token.
func (r *PhantomRegistry) Lookup(phantom string) (*PhantomEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[phantom]
	return e, ok
}

// LookupByEnv finds an entry by its environment variable name.
func (r *PhantomRegistry) LookupByEnv(envVar string) (*PhantomEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byEnv[envVar]
	return e, ok
}

// GeneratePhantom produces a new phantom token: "ajp_" followed by 32 random
// bytes encoded in base64url (no padding).  The result has 256 bits of entropy.
func GeneratePhantom() (string, error) {
	b := make([]byte, phantomEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("phantom: generate random bytes: %w", err)
	}
	return phantomPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Fingerprint returns a safe-to-log identifier for a phantom token:
// "sha256:<first 16 hex chars>".  Never log the full phantom value.
func Fingerprint(phantom string) string {
	h := sha256.Sum256([]byte(phantom))
	return fmt.Sprintf("sha256:%x", h[:8]) // 8 bytes = 16 hex chars
}

// ValidateRequest checks whether a request carrying the given phantom token is
// allowed to proceed to destHost with the given HTTP method and path.
//
// Returns nil if the request is permitted, or a descriptive error if it
// violates the entry's access policy.
func (r *PhantomRegistry) ValidateRequest(phantom, destHost, method, reqPath string) error {
	r.mu.RLock()
	entry, ok := r.entries[phantom]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("phantom: unknown token (fingerprint %s)", Fingerprint(phantom))
	}

	// Check allowed hosts.
	if len(entry.AllowedHosts) > 0 {
		hostOK := false
		normDest := strings.ToLower(destHost)
		for _, h := range entry.AllowedHosts {
			if strings.ToLower(h) == normDest {
				hostOK = true
				break
			}
		}
		if !hostOK {
			return fmt.Errorf("phantom: host %q not allowed for credential %q (fingerprint %s)",
				destHost, entry.CredentialID, Fingerprint(phantom))
		}
	}

	// Check allowed methods.
	if len(entry.AllowedMethods) > 0 {
		methodOK := false
		normMethod := strings.ToUpper(method)
		for _, m := range entry.AllowedMethods {
			if strings.ToUpper(m) == normMethod {
				methodOK = true
				break
			}
		}
		if !methodOK {
			return fmt.Errorf("phantom: method %q not allowed for credential %q (fingerprint %s)",
				method, entry.CredentialID, Fingerprint(phantom))
		}
	}

	// Check allowed paths (glob matching).
	if len(entry.AllowedPaths) > 0 {
		pathOK := false
		for _, pattern := range entry.AllowedPaths {
			if matched, err := path.Match(pattern, reqPath); err == nil && matched {
				pathOK = true
				break
			}
		}
		if !pathOK {
			return fmt.Errorf("phantom: path %q not allowed for credential %q (fingerprint %s)",
				reqPath, entry.CredentialID, Fingerprint(phantom))
		}
	}

	return nil
}

// Clear removes all entries from the registry (e.g. at session end).
func (r *PhantomRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[string]*PhantomEntry)
	r.byEnv = make(map[string]*PhantomEntry)
}
