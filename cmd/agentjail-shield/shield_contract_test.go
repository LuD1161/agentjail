package main

import (
	"regexp"
	"testing"
)

// ---- Shared, OS-agnostic contract sanity (ADR 0039) ----

// TestSensitiveFilePatterns_CompileAndCoverBoth verifies every contract
// pattern compiles as a Go regexp (a reasonable proxy for sbpl-compatibility
// -- sbpl's engine is stricter, but a pattern that doesn't even compile as a
// standard regex is certainly wrong) and that at least one Write-only and
// one Read+Write entry exist (regression guard: FIX4 moved this list out of
// shield_darwin.go's sensitiveWriteRegexes/sensitiveReadRegexes; losing an
// entry during the move would silently narrow the deny surface).
func TestSensitiveFilePatterns_CompileAndCoverBoth(t *testing.T) {
	patterns := SensitiveFilePatterns()
	if len(patterns) == 0 {
		t.Fatal("SensitiveFilePatterns() returned no entries")
	}
	var sawWriteOnly, sawReadWrite bool
	for _, p := range patterns {
		if p.Regex == "" {
			t.Errorf("PatternDeny with empty Regex: %+v", p)
		}
		if !p.Read && !p.Write {
			t.Errorf("PatternDeny %q applies to neither read nor write", p.Regex)
		}
		if _, err := regexp.Compile(p.Regex); err != nil {
			t.Errorf("pattern %q does not compile as a regex: %v", p.Regex, err)
		}
		if p.Write && !p.Read {
			sawWriteOnly = true
		}
		if p.Write && p.Read {
			sawReadWrite = true
		}
	}
	if !sawWriteOnly {
		t.Error("expected at least one write-only pattern (e.g. .env)")
	}
	if !sawReadWrite {
		t.Error("expected at least one read+write pattern (e.g. id_rsa)")
	}
}

// TestNoNetproxyFallbackPorts pins the contract's fallback port set to
// exactly {22, 80, 443} - both backends' --no-netproxy modes key off this
// value; a silent change here would silently change enforcement on both
// platforms without either _os.go file being touched.
func TestNoNetproxyFallbackPorts_IsHTTPAndHTTPS(t *testing.T) {
	got := NoNetproxyFallbackPorts()
	want := map[int]bool{22: true, 80: true, 443: true}
	if len(got) != len(want) {
		t.Fatalf("NoNetproxyFallbackPorts() = %v, want exactly %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected fallback port %d", p)
		}
	}
}

// TestPerFileGrants_KnownHostsIsReadOnlyPerFile verifies the FIX3 contract
// shape: known_hosts must be a PerFile, ReadOnly grant (never ReadWrite --
// see shield_contract.go's doc comment on why write is deliberately
// withheld).
func TestPerFileGrants_KnownHostsIsReadOnlyPerFile(t *testing.T) {
	grants := PerFileGrants()
	var found bool
	for _, g := range grants {
		if g.Path != ".ssh/known_hosts" {
			continue
		}
		found = true
		if !g.PerFile {
			t.Errorf("known_hosts grant must have PerFile=true, got %+v", g)
		}
		if g.Mode != ReadOnly {
			t.Errorf("known_hosts grant must have Mode=ReadOnly, got %+v", g)
		}
	}
	if !found {
		t.Fatal("PerFileGrants() missing .ssh/known_hosts")
	}
	if got := KnownHostsGrant(); got.Path != ".ssh/known_hosts" || got.Mode != ReadOnly || !got.PerFile {
		t.Errorf("KnownHostsGrant() = %+v, want ReadOnly PerFile .ssh/known_hosts", got)
	}
}

// TestAccessMode_String is a light sanity check on the AccessMode Stringer
// used in test failure messages and any future --profile-print output.
func TestAccessMode_String(t *testing.T) {
	if ReadOnly.String() != "read-only" {
		t.Errorf("ReadOnly.String() = %q, want %q", ReadOnly.String(), "read-only")
	}
	if ReadWrite.String() != "read-write" {
		t.Errorf("ReadWrite.String() = %q, want %q", ReadWrite.String(), "read-write")
	}
}

// TestSensitiveMCPCommandDirs_CoversKnownCredentialDirs pins the P3 contract
// set: an agent that poisons ~/.claude.json's mcpServers[].command must be
// blocked from widening its grant into any of these directories.
func TestSensitiveMCPCommandDirs_CoversKnownCredentialDirs(t *testing.T) {
	want := map[string]bool{".ssh": true, ".aws": true, ".gnupg": true}
	got := SensitiveMCPCommandDirs()
	if len(got) != len(want) {
		t.Fatalf("SensitiveMCPCommandDirs() = %v, want exactly %v", got, want)
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected entry %q in SensitiveMCPCommandDirs()", d)
		}
	}
}

// TestConfigCredentialSubdirs_CoversKnownCredentialStores pins the P4
// contract set: ~/.config subdirectories that must stay unreadable even
// though ~/.config itself is broadly granted for legitimate MCP configs.
func TestConfigCredentialSubdirs_CoversKnownCredentialStores(t *testing.T) {
	got := ConfigCredentialSubdirs()
	if len(got) == 0 {
		t.Fatal("ConfigCredentialSubdirs() returned no entries")
	}
	want := map[string]bool{"gh": true, "gcloud": true, "containers": true}
	seen := make(map[string]bool, len(got))
	for _, d := range got {
		if d == "" {
			t.Error("ConfigCredentialSubdirs() contains an empty entry")
		}
		seen[d] = true
	}
	for w := range want {
		if !seen[w] {
			t.Errorf("ConfigCredentialSubdirs() missing expected entry %q", w)
		}
	}
}
