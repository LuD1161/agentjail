package main

import (
	"net"
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

// TestPerFileGrants_SSHConfigIsReadOnlyScoped verifies the ADR 0056 Task D
// contract shape: .ssh/config is a per-file READ-ONLY carve-out alongside
// .ssh/known_hosts, and this narrow grant does not widen into write access on
// .ssh/config or into broader ~/.ssh access (a private key file, or the bare
// .ssh directory itself). Private key FILE reads must stay denied by design
// (SensitiveFilePatterns covers id_rsa/id_ed25519/etc, and .ssh is
// listed in SensitiveMCPCommandDirs precisely so it is never granted as a
// directory) -- ssh auth for a sandboxed agent goes through ssh-agent, never
// a config-driven read hole. See docs/adr/0056-ssh-agent-pinned-identityfile-blindspot.md.
func TestPerFileGrants_SSHConfigIsReadOnlyScoped(t *testing.T) {
	grants := PerFileGrants()

	wantReadOnly := map[string]bool{
		".ssh/config":      false,
		".ssh/known_hosts": false,
	}
	for _, g := range grants {
		if _, ok := wantReadOnly[g.Path]; !ok {
			continue
		}
		wantReadOnly[g.Path] = true
		if !g.PerFile {
			t.Errorf("grant %q must have PerFile=true, got %+v", g.Path, g)
		}
		if g.Mode != ReadOnly {
			t.Errorf("grant %q must have Mode=ReadOnly, got %+v", g.Path, g)
		}
	}
	for path, found := range wantReadOnly {
		if !found {
			t.Errorf("PerFileGrants() missing expected read-only grant %q", path)
		}
	}

	// No grant anywhere in the per-file list may name .ssh/config with write
	// access, and none may name a private key file or the bare .ssh
	// directory -- a narrow per-file read carve-out must never imply
	// broader ~/.ssh access.
	disallowed := map[string]bool{
		".ssh":            true,
		".ssh/id_rsa":     true,
		".ssh/id_ed25519": true,
	}
	for _, g := range grants {
		if g.Path == ".ssh/config" && g.Mode == ReadWrite {
			t.Errorf("PerFileGrants() must not grant write access to .ssh/config, got %+v", g)
		}
		if disallowed[g.Path] {
			t.Errorf("PerFileGrants() must not grant broader ~/.ssh access via %q, got %+v", g.Path, g)
		}
	}

	// Confirm the broader contract too: .ssh is one of the top-level
	// directories that must NEVER be granted (SensitiveMCPCommandDirs), so a
	// directory-level grant for ~/.ssh cannot exist by construction.
	var sawSSHDir bool
	for _, d := range SensitiveMCPCommandDirs() {
		if d == ".ssh" {
			sawSSHDir = true
		}
	}
	if !sawSSHDir {
		t.Error("SensitiveMCPCommandDirs() must include \".ssh\" -- the per-file config/known_hosts carve-outs rely on .ssh never being a directory-level grant")
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

// ---- Cloud-metadata (IMDS) egress guard contract (P2/M2, ADR 0049) ----

// TestCloudMetadataDenyIPs_CoversKnownEndpoints pins the shared list to the
// two addresses the finding calls out explicitly: AWS/GCP/Azure/OpenStack/
// Alibaba's shared IPv4 IMDS address and AWS's IPv6 IMDS address. A silent
// change here would silently narrow what the launch-time guard checks.
func TestCloudMetadataDenyIPs_CoversKnownEndpoints(t *testing.T) {
	ips := CloudMetadataDenyIPs()
	want := map[string]bool{"169.254.169.254": false, "fd00:ec2::254": false}
	for _, m := range ips {
		if m.IP == "" {
			t.Errorf("CloudMetadataDenyIP with empty IP: %+v", m)
		}
		if m.Note == "" {
			t.Errorf("CloudMetadataDenyIP %q has no Note", m.IP)
		}
		if net.ParseIP(m.IP) == nil {
			t.Errorf("CloudMetadataDenyIP %q does not parse as an IP", m.IP)
		}
		if _, ok := want[m.IP]; ok {
			want[m.IP] = true
		}
	}
	for ip, seen := range want {
		if !seen {
			t.Errorf("CloudMetadataDenyIPs() missing expected endpoint %q", ip)
		}
	}
}

// TestIsCloudMetadataIP covers the exact-match, CIDR-match, non-match, and
// malformed-input cases for the membership helper the launch-time guard's
// documentation and the shared contract both describe.
func TestIsCloudMetadataIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"exact AWS/GCP/Azure IMDS IPv4", "169.254.169.254", true},
		{"exact AWS IMDS IPv6", "fd00:ec2::254", true},
		{"other address in the 169.254.0.0/16 link-local block", "169.254.1.1", true},
		{"link-local block boundary, lowest address", "169.254.0.0", true},
		{"link-local block boundary, highest address", "169.254.255.255", true},
		{"ordinary public IPv4, not metadata", "8.8.8.8", false},
		{"ordinary private IPv4, not metadata", "10.0.0.1", false},
		{"loopback, not metadata", "127.0.0.1", false},
		{"unrelated IPv6, not metadata", "2001:4860:4860::8888", false},
		{"empty string", "", false},
		{"not an IP at all", "169.254.169.254.evil.example.com", false},
		{"hostname, not a literal IP", "metadata.google.internal", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsCloudMetadataIP(c.ip); got != c.want {
				t.Errorf("IsCloudMetadataIP(%q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

// TestCapMetadataIPFilter_IsDistinctKey is a compile-time-adjacent sanity
// check that the capability key exists and is distinct from the other two
// -- the real "both backends name it Unsupported" assertion lives in
// shield_darwin_fixes_test.go (darwin) and shield_linux_netplan_test.go
// (linux), where the OS-tagged Unsupported maps are actually constructed.
func TestCapMetadataIPFilter_IsDistinctKey(t *testing.T) {
	keys := map[CapabilityKey]bool{
		CapFilenamePatternDeny: true,
		CapLoopbackScopedBind:  true,
		CapMetadataIPFilter:    true,
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 distinct CapabilityKey values, got %d", len(keys))
	}
}
