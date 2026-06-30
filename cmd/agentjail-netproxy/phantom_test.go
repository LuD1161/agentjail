package main

import (
	"strings"
	"sync"
	"testing"
)

func TestGeneratePhantom(t *testing.T) {
	tok, err := GeneratePhantom()
	if err != nil {
		t.Fatalf("GeneratePhantom() error: %v", err)
	}
	if !strings.HasPrefix(tok, "ajp_") {
		t.Fatalf("GeneratePhantom() = %q; want ajp_ prefix", tok)
	}
	// base64url of 32 bytes = 43 chars (no padding); total = 4 + 43 = 47
	if len(tok) != 47 {
		t.Fatalf("GeneratePhantom() length = %d; want 47", len(tok))
	}

	// Two tokens must differ (probabilistic but effectively certain).
	tok2, err := GeneratePhantom()
	if err != nil {
		t.Fatalf("GeneratePhantom() second call error: %v", err)
	}
	if tok == tok2 {
		t.Fatal("GeneratePhantom() returned identical tokens")
	}
}

func TestFingerprint(t *testing.T) {
	fp := Fingerprint("ajp_test_token")
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("Fingerprint() = %q; want sha256: prefix", fp)
	}
	// "sha256:" (7) + 16 hex chars = 23
	if len(fp) != 23 {
		t.Fatalf("Fingerprint() length = %d; want 23", len(fp))
	}

	// Same input must produce same fingerprint.
	fp2 := Fingerprint("ajp_test_token")
	if fp != fp2 {
		t.Fatal("Fingerprint() not deterministic")
	}

	// Different input must produce different fingerprint.
	fp3 := Fingerprint("ajp_other_token")
	if fp == fp3 {
		t.Fatal("Fingerprint() collision on different inputs")
	}
}

func TestRegistryRegisterAndLookup(t *testing.T) {
	reg := NewPhantomRegistry()

	entry := &PhantomEntry{
		CredentialID: "github",
		Phantom:      "ajp_test_github_token",
		EnvVar:       "GITHUB_TOKEN",
		AllowedHosts: []string{"api.github.com"},
	}

	if err := reg.Register(entry); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// Lookup by phantom token.
	got, ok := reg.Lookup("ajp_test_github_token")
	if !ok {
		t.Fatal("Lookup() returned false for registered token")
	}
	if got.CredentialID != "github" {
		t.Fatalf("Lookup() credential ID = %q; want %q", got.CredentialID, "github")
	}

	// Lookup by env var.
	got2, ok := reg.LookupByEnv("GITHUB_TOKEN")
	if !ok {
		t.Fatal("LookupByEnv() returned false for registered env var")
	}
	if got2.Phantom != "ajp_test_github_token" {
		t.Fatalf("LookupByEnv() phantom = %q; want %q", got2.Phantom, "ajp_test_github_token")
	}

	// Unknown lookup.
	_, ok = reg.Lookup("ajp_nonexistent")
	if ok {
		t.Fatal("Lookup() returned true for unknown token")
	}
	_, ok = reg.LookupByEnv("NONEXISTENT_VAR")
	if ok {
		t.Fatal("LookupByEnv() returned true for unknown env var")
	}
}

func TestRegistryRegisterCollisions(t *testing.T) {
	reg := NewPhantomRegistry()

	entry1 := &PhantomEntry{
		CredentialID: "github",
		Phantom:      "ajp_token_1",
		EnvVar:       "GITHUB_TOKEN",
	}
	if err := reg.Register(entry1); err != nil {
		t.Fatalf("Register() first entry error: %v", err)
	}

	// Duplicate phantom token.
	entry2 := &PhantomEntry{
		CredentialID: "github-dup",
		Phantom:      "ajp_token_1",
		EnvVar:       "OTHER_TOKEN",
	}
	if err := reg.Register(entry2); err == nil {
		t.Fatal("Register() should fail on phantom collision")
	}

	// Duplicate env var.
	entry3 := &PhantomEntry{
		CredentialID: "github-dup2",
		Phantom:      "ajp_token_2",
		EnvVar:       "GITHUB_TOKEN",
	}
	if err := reg.Register(entry3); err == nil {
		t.Fatal("Register() should fail on env var collision")
	}
}

func TestRegistryRegisterValidation(t *testing.T) {
	reg := NewPhantomRegistry()

	if err := reg.Register(nil); err == nil {
		t.Fatal("Register(nil) should return error")
	}
	if err := reg.Register(&PhantomEntry{Phantom: "", EnvVar: "X"}); err == nil {
		t.Fatal("Register() with empty phantom should return error")
	}
	if err := reg.Register(&PhantomEntry{Phantom: "ajp_x", EnvVar: ""}); err == nil {
		t.Fatal("Register() with empty env var should return error")
	}
}

func TestValidateRequestHost(t *testing.T) {
	reg := NewPhantomRegistry()
	_ = reg.Register(&PhantomEntry{
		CredentialID: "github",
		Phantom:      "ajp_gh",
		EnvVar:       "GH",
		AllowedHosts: []string{"api.github.com"},
	})

	if err := reg.ValidateRequest("ajp_gh", "api.github.com", "GET", "/repos"); err != nil {
		t.Fatalf("ValidateRequest() allowed host: %v", err)
	}
	if err := reg.ValidateRequest("ajp_gh", "evil.com", "GET", "/repos"); err == nil {
		t.Fatal("ValidateRequest() should deny disallowed host")
	}
}

func TestValidateRequestHostCaseInsensitive(t *testing.T) {
	reg := NewPhantomRegistry()
	_ = reg.Register(&PhantomEntry{
		CredentialID: "github",
		Phantom:      "ajp_gh2",
		EnvVar:       "GH2",
		AllowedHosts: []string{"API.GitHub.Com"},
	})

	if err := reg.ValidateRequest("ajp_gh2", "api.github.com", "GET", "/"); err != nil {
		t.Fatalf("ValidateRequest() case-insensitive host: %v", err)
	}
}

func TestValidateRequestMethod(t *testing.T) {
	reg := NewPhantomRegistry()
	_ = reg.Register(&PhantomEntry{
		CredentialID:   "api",
		Phantom:        "ajp_api",
		EnvVar:         "API",
		AllowedMethods: []string{"GET", "POST"},
	})

	if err := reg.ValidateRequest("ajp_api", "any.host", "GET", "/"); err != nil {
		t.Fatalf("ValidateRequest() allowed method: %v", err)
	}
	if err := reg.ValidateRequest("ajp_api", "any.host", "post", "/"); err != nil {
		t.Fatalf("ValidateRequest() method case-insensitive: %v", err)
	}
	if err := reg.ValidateRequest("ajp_api", "any.host", "DELETE", "/"); err == nil {
		t.Fatal("ValidateRequest() should deny disallowed method")
	}
}

func TestValidateRequestPath(t *testing.T) {
	reg := NewPhantomRegistry()
	_ = reg.Register(&PhantomEntry{
		CredentialID: "scoped",
		Phantom:      "ajp_scoped",
		EnvVar:       "SCOPED",
		AllowedPaths: []string{"/repos/LuD1161/*"},
	})

	if err := reg.ValidateRequest("ajp_scoped", "any.host", "GET", "/repos/LuD1161/agentjail"); err != nil {
		t.Fatalf("ValidateRequest() allowed path: %v", err)
	}
	if err := reg.ValidateRequest("ajp_scoped", "any.host", "GET", "/repos/other/repo"); err == nil {
		t.Fatal("ValidateRequest() should deny disallowed path")
	}
}

func TestValidateRequestEmptyConstraints(t *testing.T) {
	reg := NewPhantomRegistry()
	_ = reg.Register(&PhantomEntry{
		CredentialID: "open",
		Phantom:      "ajp_open",
		EnvVar:       "OPEN",
		// No host/method/path restrictions.
	})

	if err := reg.ValidateRequest("ajp_open", "any.host", "DELETE", "/anything"); err != nil {
		t.Fatalf("ValidateRequest() no restrictions: %v", err)
	}
}

func TestValidateRequestUnknownToken(t *testing.T) {
	reg := NewPhantomRegistry()
	if err := reg.ValidateRequest("ajp_unknown", "host", "GET", "/"); err == nil {
		t.Fatal("ValidateRequest() should fail for unknown token")
	}
}

func TestClear(t *testing.T) {
	reg := NewPhantomRegistry()
	_ = reg.Register(&PhantomEntry{
		CredentialID: "test",
		Phantom:      "ajp_clear",
		EnvVar:       "CLEAR",
	})

	reg.Clear()

	if _, ok := reg.Lookup("ajp_clear"); ok {
		t.Fatal("Lookup() should return false after Clear()")
	}
	if _, ok := reg.LookupByEnv("CLEAR"); ok {
		t.Fatal("LookupByEnv() should return false after Clear()")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	reg := NewPhantomRegistry()
	const n = 100

	// Pre-register entries.
	for i := 0; i < n; i++ {
		tok, _ := GeneratePhantom()
		_ = reg.Register(&PhantomEntry{
			CredentialID: "cred",
			Phantom:      tok,
			EnvVar:       strings.Replace(tok, "ajp_", "ENV_", 1),
			AllowedHosts: []string{"api.example.com"},
		})
	}

	// Concurrent reads must not race.
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Exercise all read paths.
			reg.Lookup("ajp_nonexistent")
			reg.LookupByEnv("NONEXISTENT")
			_ = reg.ValidateRequest("ajp_nonexistent", "host", "GET", "/")
		}()
	}
	wg.Wait()
}
