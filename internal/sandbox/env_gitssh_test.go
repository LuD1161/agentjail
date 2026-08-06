package sandbox

import (
	"reflect"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// fakeGetenv builds a getenv func closed over a fixed map, for pure-function
// testing of AgentGitSSHEnv without touching real process env.
func fakeGetenv(vars map[string]string) func(string) string {
	return func(key string) string {
		return vars[key]
	}
}

func TestAgentGitSSHEnv_UserValuePreservedVerbatim(t *testing.T) {
	getenv := fakeGetenv(map[string]string{
		"GIT_SSH_COMMAND": "ssh -o IdentityAgent=none -F /custom/config",
		"SSH_AUTH_SOCK":   "/tmp/agent.sock",
	})

	got := AgentGitSSHEnv(getenv, SSHAuthSock{Path: "/tmp/agent.sock"})
	want := []string{"GIT_SSH_COMMAND=ssh -o IdentityAgent=none -F /custom/config"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, kv := range got {
		if EnvVarName(kv) == "AGENTJAIL_SSH_OVERRIDE" {
			t.Fatalf("marker must not appear when user GIT_SSH_COMMAND is preserved: %v", got)
		}
	}
}

func TestAgentGitSSHEnv_DefaultDenyDoesNotPreserveHostOverride(t *testing.T) {
	got := AgentGitSSHEnv(fakeGetenv(map[string]string{
		"GIT_SSH_COMMAND": "ssh -F /host-controlled/config",
		"SSH_AUTH_SOCK":   "/tmp/ambient.sock",
	}), SSHAuthSock{})
	if got != nil {
		t.Fatalf("ambient GIT_SSH_COMMAND survived without delegation: %v", got)
	}
}

func TestAgentGitSSHEnv_OptOut(t *testing.T) {
	cases := []string{"1", "true", "yes", "TRUE"}
	for _, v := range cases {
		getenv := fakeGetenv(map[string]string{
			"AGENTJAIL_NO_SSH_OVERRIDE": v,
			"SSH_AUTH_SOCK":             "/tmp/agent.sock",
		})
		got := AgentGitSSHEnv(getenv, SSHAuthSock{Path: "/tmp/agent.sock"})
		if got != nil {
			t.Errorf("AGENTJAIL_NO_SSH_OVERRIDE=%q: got %v, want nil", v, got)
		}
	}
}

func TestAgentGitSSHEnv_OptOutFalsyValuesDoNotOptOut(t *testing.T) {
	cases := []string{"0", "false", "False"}
	for _, v := range cases {
		getenv := fakeGetenv(map[string]string{
			"AGENTJAIL_NO_SSH_OVERRIDE": v,
			"SSH_AUTH_SOCK":             "/tmp/agent.sock",
		})
		got := AgentGitSSHEnv(getenv, SSHAuthSock{Path: "/tmp/agent.sock"})
		if got == nil {
			t.Errorf("AGENTJAIL_NO_SSH_OVERRIDE=%q should NOT opt out, got nil", v)
		}
	}
}

func TestAgentGitSSHEnv_NormalPath(t *testing.T) {
	getenv := fakeGetenv(map[string]string{
		"SSH_AUTH_SOCK": "/tmp/agent.sock",
	})

	got := AgentGitSSHEnv(getenv, SSHAuthSock{Path: "/tmp/agent.sock"})
	want := []string{
		"GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent='/tmp/agent.sock'",
		"AGENTJAIL_SSH_OVERRIDE=1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAgentGitSSHEnv_SockWithSpaceIsSingleQuoted(t *testing.T) {
	getenv := fakeGetenv(map[string]string{
		"SSH_AUTH_SOCK": "/tmp/my agent dir/agent.sock",
	})

	got := AgentGitSSHEnv(getenv, SSHAuthSock{Path: "/tmp/my agent dir/agent.sock"})
	wantCmd := "GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent='/tmp/my agent dir/agent.sock'"
	if len(got) == 0 || got[0] != wantCmd {
		t.Fatalf("got %v, want first element %q", got, wantCmd)
	}
	if len(got) != 2 || got[1] != "AGENTJAIL_SSH_OVERRIDE=1" {
		t.Fatalf("expected marker present, got %v", got)
	}
}

func TestAgentGitSSHEnv_EmptySockYieldsNil(t *testing.T) {
	getenv := fakeGetenv(map[string]string{
		"SSH_AUTH_SOCK": "",
	})
	got := AgentGitSSHEnv(getenv, SSHAuthSock{})
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestAgentGitSSHEnv_ControlCharSockYieldsNil(t *testing.T) {
	cases := []string{
		"/tmp/agent\nsock",
		"/tmp/agent\x00sock",
		"/tmp/agent\tsock",
	}
	for _, sock := range cases {
		getenv := fakeGetenv(map[string]string{
			"SSH_AUTH_SOCK": sock,
		})
		got := AgentGitSSHEnv(getenv, SSHAuthSock{})
		if got != nil {
			t.Errorf("sock %q: got %v, want nil (fail-closed on control char)", sock, got)
		}
	}
}

func TestShellSingleQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/var/x", "'/var/x'"},
		{"a'b", `'a'\''b'`},
		{"", "''"},
		{"/tmp/my sock", "'/tmp/my sock'"},
		{"a''b", `'a'\'''\''b'`},
	}
	for _, c := range cases {
		got := shellSingleQuote(c.in)
		if got != c.want {
			t.Errorf("shellSingleQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRemoveEnvKeys(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"GIT_SSH_COMMAND=ssh -o Foo=bar",
		"AGENTJAIL_SSH_OVERRIDE=1",
		"HOME=/home/user",
	}
	got := RemoveEnvKeys(env, "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE")
	want := []string{"PATH=/usr/bin", "HOME=/home/user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRemoveEnvKeys_NoMatchesLeavesEnvUnchanged(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/home/user"}
	got := RemoveEnvKeys(env, "GIT_SSH_COMMAND")
	want := []string{"PATH=/usr/bin", "HOME=/home/user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestAssembly_DedupeThenAppend simulates the shield's real assembly: a
// clean env that already contains a user GIT_SSH_COMMAND (because it was
// listed in cfg.Secrets.EnvPassthrough and survived BuildCleanEnv) plus a
// SPOOFED AGENTJAIL_SSH_OVERRIDE=1 the host tried to sneak through
// EnvPassthrough. After RemoveEnvKeys + append(AgentGitSSHEnv(...)), exactly
// one GIT_SSH_COMMAND must remain, and the marker (if present at all) must
// be the shield-appended one, not the spoofed one.
func TestAssembly_DedupeThenAppend(t *testing.T) {
	strip := true
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			StripOnLaunch:  &strip,
			EnvPassthrough: []string{"GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE"},
		},
	}
	hostEnv := []string{
		"PATH=/usr/bin",
		"GIT_SSH_COMMAND=ssh -F /passthrough/config",
		"AGENTJAIL_SSH_OVERRIDE=1", // spoofed by the host; must not survive as-is
	}

	env := BuildCleanEnv(hostEnv, cfg)
	env = StripEnv(env, cfg)

	// Sanity: BuildCleanEnv respected EnvPassthrough, so both survived so far
	// (this is the vulnerable intermediate state the dedupe step must fix).
	foundSpoofedMarker := false
	for _, kv := range env {
		if kv == "AGENTJAIL_SSH_OVERRIDE=1" {
			foundSpoofedMarker = true
		}
	}
	if !foundSpoofedMarker {
		t.Fatalf("test setup invalid: expected spoofed marker to survive BuildCleanEnv+StripEnv, env=%v", env)
	}

	// Now the shield's real wiring: dedupe, then append the pure decision.
	env = RemoveEnvKeys(env, "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE")
	// getenv here reads the "host" - since the host itself set
	// GIT_SSH_COMMAND, AgentGitSSHEnv must preserve it verbatim (and add no
	// marker), per rule 1.
	env = append(env, AgentGitSSHEnv(fakeGetenv(map[string]string{
		"GIT_SSH_COMMAND": "ssh -F /passthrough/config",
	}), SSHAuthSock{Path: "/tmp/agent.sock"})...)

	gitSSHCount := 0
	markerCount := 0
	var finalGitSSH string
	for _, kv := range env {
		switch EnvVarName(kv) {
		case "GIT_SSH_COMMAND":
			gitSSHCount++
			finalGitSSH = kv
		case "AGENTJAIL_SSH_OVERRIDE":
			markerCount++
		}
	}

	if gitSSHCount != 1 {
		t.Fatalf("expected exactly one GIT_SSH_COMMAND, got %d: %v", gitSSHCount, env)
	}
	if finalGitSSH != "GIT_SSH_COMMAND=ssh -F /passthrough/config" {
		t.Fatalf("expected user value preserved verbatim, got %q", finalGitSSH)
	}
	// The spoofed marker must be gone; since the host set its own
	// GIT_SSH_COMMAND, AgentGitSSHEnv must not add a new marker either.
	if markerCount != 0 {
		t.Fatalf("expected 0 markers (spoofed one removed, none re-added), got %d: %v", markerCount, env)
	}
}

// TestAssembly_SpoofedMarkerNeverSurvivesWhenOverrideInjected covers the
// other branch: no user GIT_SSH_COMMAND, so the shield injects its own
// override and its own marker - but a host-spoofed AGENTJAIL_SSH_OVERRIDE=1
// present before dedupe must be the one removed, and the surviving marker
// must be the one appended by AgentGitSSHEnv, not proof the spoof "worked".
func TestAssembly_SpoofedMarkerNeverSurvivesWhenOverrideInjected(t *testing.T) {
	strip := true
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			StripOnLaunch:  &strip,
			EnvPassthrough: []string{"AGENTJAIL_SSH_OVERRIDE"},
		},
	}
	hostEnv := []string{
		"PATH=/usr/bin",
		"AGENTJAIL_SSH_OVERRIDE=1", // spoofed; no GIT_SSH_COMMAND set by host
	}

	env := BuildCleanEnv(hostEnv, cfg)
	env = StripEnv(env, cfg)
	env = RemoveEnvKeys(env, "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE")
	env = append(env, AgentGitSSHEnv(fakeGetenv(map[string]string{
		"SSH_AUTH_SOCK": "/tmp/agent.sock",
	}), SSHAuthSock{Path: "/tmp/agent.sock"})...)

	markerCount := 0
	for _, kv := range env {
		if kv == "AGENTJAIL_SSH_OVERRIDE=1" {
			markerCount++
		}
	}
	if markerCount != 1 {
		t.Fatalf("expected exactly one marker (the shield-appended one), got %d: %v", markerCount, env)
	}
}
