// Package apparmor renders and installs the scoped AppArmor profile that lets
// agentjail-shield create an unprivileged user namespace on hosts with
// kernel.apparmor_restrict_unprivileged_userns=1 (Ubuntu 23.10+), without
// relaxing the restriction system-wide. See ADR 0104-shield-apparmor-userns.
//
// The interface + shared contract live here (tag-free); per-OS implementors
// live in apparmor_linux.go / apparmor_other.go. See ADR 0034-platform-backend-shared-contract.
package apparmor

import (
	"bytes"
	"embed"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

// Errors returned by Manager implementations. Callers match with errors.Is.
var (
	// ErrNotSupported means AppArmor userns profiling is unavailable on this OS.
	ErrNotSupported = errors.New("agentjail apparmor: not supported on this platform")
	// ErrNotRoot means Install was called without the root privilege it needs.
	ErrNotRoot = errors.New("agentjail apparmor: installing the profile requires root")
	// ErrParserMissing means apparmor_parser was not found on PATH.
	ErrParserMissing = errors.New("agentjail apparmor: apparmor_parser not found")
	// ErrParserTooOld means apparmor_parser is older than 4.0 (no abi/4.0, no userns rule).
	ErrParserTooOld = errors.New("agentjail apparmor: apparmor_parser 4.x required")
)

// profileInstallPath is where apparmor_parser expects loadable profiles.
// The basename becomes the on-disk profile filename.
const profileInstallPath = "/etc/apparmor.d/agentjail-shield"

// usernsFeaturePath is present (readable) only on AppArmor 4.x kernels that
// expose the permission-stable32 policy feature backing the userns rule.
const usernsFeaturePath = "/sys/kernel/security/apparmor/features/policy/permstable32"

//go:embed profile.tmpl
var profileTemplateFS embed.FS

// profileTemplate is parsed once; a bad embedded template is a build-time bug.
var profileTemplate = template.Must(
	template.ParseFS(profileTemplateFS, "profile.tmpl"),
)

// Version is a parsed apparmor_parser version (patch is 0 when absent).
type Version struct {
	Major int
	Minor int
	Patch int
}

// AtLeast reports whether v is >= o.
func (v Version) AtLeast(o Version) bool {
	if v.Major != o.Major {
		return v.Major > o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor > o.Minor
	}
	return v.Patch >= o.Patch
}

func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// minParserVersion is the floor for the abi <abi/4.0> + userns profile.
var minParserVersion = Version{Major: 4}

// versionRe matches "...version 4.0.1" (patch optional) in apparmor_parser output.
var versionRe = regexp.MustCompile(`version\s+(\d+)\.(\d+)(?:\.(\d+))?`)

// parseParserVersion extracts the version from `apparmor_parser --version` output.
// Returns ok=false when no version token is present.
func parseParserVersion(output string) (Version, bool) {
	m := versionRe.FindStringSubmatch(output)
	if m == nil {
		return Version{}, false
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.Patch, _ = strconv.Atoi(m[3])
	}
	return v, true
}

// Availability describes whether this host can load the scoped userns profile.
type Availability struct {
	ParserFound   bool    // apparmor_parser is on PATH
	ParserVersion Version // parsed version (zero when ParserFound is false)
	UsernsFeature bool    // the permstable32 policy feature is exposed
	Supported     bool    // parser found AND version >= 4.0
}

// Manager renders and installs the agentjail-shield AppArmor userns profile.
// Render is OS-agnostic (pure text); Available/Install are per-OS.
type Manager interface {
	// Available detects whether AppArmor 4.x can load the scoped profile.
	Available() (Availability, error)
	// Render returns the profile text attached to the binaries under installDir
	// (the agentjail bin directory, e.g. ~/.agentjail/bin).
	Render(installDir string) string
	// Install writes the profile to /etc/apparmor.d and loads it. Needs root.
	Install(installDir string) error
}

// renderer is the shared, OS-agnostic Render implementor embedded into every
// per-OS Manager so the profile text is generated from one source of truth.
// See ADR 0034-platform-backend-shared-contract.
type renderer struct{}

// Render templates the $HOME-relative attach path into the profile. The
// {,-shield} glob covers both multicall re-exec paths (ADR 0103).
func (renderer) Render(installDir string) string {
	attach := strings.TrimRight(installDir, "/") + "/agentjail{,-shield}"
	var buf bytes.Buffer
	// Execute cannot fail: the template is valid and AttachPath is a plain string.
	_ = profileTemplate.Execute(&buf, struct{ AttachPath string }{AttachPath: attach})
	return buf.String()
}
