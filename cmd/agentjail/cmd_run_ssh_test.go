package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/sshagent"
)

type promptReadWriter struct {
	io.Reader
	io.Writer
}

func TestParseRunOptionsConsumesGitSSHOnlyAsLeadingLaunchFlag(t *testing.T) {
	options, rest := parseRunOptions([]string{"--git-ssh", "--tunnel", "--verbose", "--", "claude", "--git-ssh"})
	if !options.gitSSH || options.noGitSSH || !options.tunnelMode || options.noSandbox || !options.verbose {
		t.Fatalf("options = %#v", options)
	}
	if len(rest) != 3 || rest[2] != "--git-ssh" {
		t.Fatalf("child args changed: %v", rest)
	}
}

func TestRunHelpDocumentsSSHForwarding(t *testing.T) {
	if runCmd.Long == "" || claudeCmd.Long == "" {
		t.Fatal("run command help unexpectedly empty")
	}
	if !strings.Contains(runCmd.Long, "--git-ssh") || !strings.Contains(claudeCmd.Long, "--git-ssh") {
		t.Fatal("Git-over-SSH flag missing from run or compatibility help")
	}
	if !strings.Contains(runCmd.Long, "--require-tunnel") {
		t.Fatal("required-tunnel contract missing from run help")
	}
}

func TestParseRunOptionsGitSSHOverrides(t *testing.T) {
	on, rest := parseRunOptions([]string{"--git-ssh", "--", "codex"})
	if !on.gitSSH || on.noGitSSH || len(rest) != 2 {
		t.Fatalf("enabled options = %#v, rest = %v", on, rest)
	}
	off, rest := parseRunOptions([]string{"--no-git-ssh", "--", "cursor"})
	if off.gitSSH || !off.noGitSSH || len(rest) != 2 {
		t.Fatalf("disabled options = %#v, rest = %v", off, rest)
	}
}

func TestRunVerboseRequiresShield(t *testing.T) {
	if got := runRunCmd([]string{"--no-sandbox", "--verbose", "--", "claude"}); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
}

func TestPromptSSHBootstrapDefaultsYes(t *testing.T) {
	home := "/home/test"
	selection := sshagent.IdentitySelection{
		Host:   "github-work",
		Paths:  []string{home + "/.ssh/id_work"},
		Source: sshagent.IdentitySelectionSSHConfig,
	}
	tests := []struct {
		answer string
		want   bool
	}{
		{answer: "\n", want: true},
		{answer: "yes\n", want: true},
		{answer: "Y\n", want: true},
		{answer: "n\n", want: false},
		{answer: "anything else\n", want: false},
	}
	for _, tt := range tests {
		t.Run(strings.TrimSpace(tt.answer), func(t *testing.T) {
			var output bytes.Buffer
			tty := promptReadWriter{Reader: strings.NewReader(tt.answer), Writer: &output}
			paths, got := promptSSHBootstrap(tty, selection, home)
			if got != tt.want {
				t.Fatalf("promptSSHBootstrap(%q) = %v, want %v", tt.answer, got, tt.want)
			}
			if got && !reflect.DeepEqual(paths, selection.Paths) {
				t.Fatalf("selected paths = %v, want %v", paths, selection.Paths)
			}
			wantPrompt := "Git SSH: load ~/.ssh/id_work into session-only OpenSSH? AgentJail never reads keys/passphrases. [Y/n] "
			if output.String() != wantPrompt {
				t.Fatalf("prompt = %q, want %q", output.String(), wantPrompt)
			}
		})
	}
}

func TestPromptSSHBootstrapChoosesOneIdentityUnlessAllIsExplicit(t *testing.T) {
	home := "/home/test"
	selection := sshagent.IdentitySelection{
		Host:   "github.com",
		Paths:  []string{home + "/.ssh/id_personal", home + "/.ssh/id_work"},
		Source: sshagent.IdentitySelectionSSHConfig,
	}
	tests := []struct {
		name       string
		answer     string
		wantPaths  []string
		wantAccept bool
	}{
		{name: "default first", answer: "\n", wantPaths: selection.Paths[:1], wantAccept: true},
		{name: "second", answer: "2\n", wantPaths: selection.Paths[1:], wantAccept: true},
		{name: "all explicit", answer: "a\n", wantPaths: selection.Paths, wantAccept: true},
		{name: "decline", answer: "n\n", wantAccept: false},
		{name: "retry invalid", answer: "wrong\n2\n", wantPaths: selection.Paths[1:], wantAccept: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			tty := promptReadWriter{Reader: strings.NewReader(tt.answer), Writer: &output}
			paths, accepted := promptSSHBootstrap(tty, selection, home)
			if accepted != tt.wantAccept || !reflect.DeepEqual(paths, tt.wantPaths) {
				t.Fatalf("selection = %v/%v, want %v/%v", paths, accepted, tt.wantPaths, tt.wantAccept)
			}
			for _, want := range []string{"Multiple SSH identities match github.com", "1. ~/.ssh/id_personal", "a. Load all identities"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("prompt missing %q: %q", want, output.String())
				}
			}
		})
	}
}

func TestShouldOfferSSHBootstrap(t *testing.T) {
	home := t.TempDir()
	noAgentWithKey := sshagent.Status{
		Readiness: sshagent.ReadinessNoAgent,
		KeyState:  sshagent.KeyStatePresent,
	}

	enabled, err := gitSSHEnabledForLaunch(runOptions{}, home)
	if err != nil {
		t.Fatal(err)
	}
	if offer := shouldOfferSSHBootstrap(runOptions{}, enabled, noAgentWithKey); !offer {
		t.Fatal("standard policy did not offer setup")
	}

	if offer := shouldOfferSSHBootstrap(runOptions{noGitSSH: true}, false, noAgentWithKey); offer {
		t.Fatal("--no-git-ssh offered setup")
	}

	ready := noAgentWithKey
	ready.Readiness = sshagent.ReadinessReady
	if offer := shouldOfferSSHBootstrap(runOptions{}, true, ready); offer {
		t.Fatal("ready agent offered setup")
	}

	withoutKeys := noAgentWithKey
	withoutKeys.KeyState = sshagent.KeyStateAbsent
	if offer := shouldOfferSSHBootstrap(runOptions{}, true, withoutKeys); offer {
		t.Fatal("automatic launch without local keys offered setup")
	}
	if offer := shouldOfferSSHBootstrap(runOptions{gitSSH: true}, true, withoutKeys); !offer {
		t.Fatal("explicit request without discovered keys did not offer setup")
	}
}

func TestShouldOfferSSHBootstrapHonorsStrictPolicyAndExplicitOverride(t *testing.T) {
	home := t.TempDir()
	policyDir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("capabilities:\n  git_ssh: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := sshagent.Status{Readiness: sshagent.ReadinessNoAgent, KeyState: sshagent.KeyStatePresent}

	enabled, err := gitSSHEnabledForLaunch(runOptions{}, home)
	if err != nil {
		t.Fatal(err)
	}
	if offer := shouldOfferSSHBootstrap(runOptions{}, enabled, status); offer {
		t.Fatal("strict policy offered setup")
	}
	explicitEnabled, err := gitSSHEnabledForLaunch(runOptions{gitSSH: true}, home)
	if err != nil {
		t.Fatal(err)
	}
	if offer := shouldOfferSSHBootstrap(runOptions{gitSSH: true}, explicitEnabled, status); !offer {
		t.Fatal("explicit override did not offer setup")
	}
}

func TestSessionSSHAgentEnvCleansTempDirWithoutMutatingCaller(t *testing.T) {
	input := []string{
		"PATH=/usr/bin:/bin",
		"TMPDIR=/var/folders/xx/yyyy/T/",
		"EMPTY=",
	}
	want := []string{
		"PATH=/usr/bin:/bin",
		"TMPDIR=/var/folders/xx/yyyy/T",
		"EMPTY=",
	}
	got := sessionSSHAgentEnv(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sessionSSHAgentEnv = %v, want %v", got, want)
	}
	if input[1] != "TMPDIR=/var/folders/xx/yyyy/T/" {
		t.Fatalf("sessionSSHAgentEnv mutated caller: %v", input)
	}

	for _, input := range [][]string{{"PATH=/usr/bin"}, {"TMPDIR="}} {
		if got := sessionSSHAgentEnv(input); !reflect.DeepEqual(got, input) {
			t.Errorf("sessionSSHAgentEnv(%v) = %v", input, got)
		}
	}
}

func TestSessionSSHAgentEnvCanonicalizesSymlinkedTempDir(t *testing.T) {
	realDir := t.TempDir()
	linkParent := t.TempDir()
	linkDir := filepath.Join(linkParent, "session-temp")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	canonicalDir, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}

	got := sessionSSHAgentEnv([]string{"TMPDIR=" + linkDir + string(filepath.Separator)})
	want := []string{"TMPDIR=" + canonicalDir}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sessionSSHAgentEnv = %v, want %v", got, want)
	}
}

func TestCompleteSSHBootstrapUsesTTYAndPreservesCommand(t *testing.T) {
	var tty bytes.Buffer
	args := []string{"/path/to/agentjail-shield", "--git-ssh", "--", "/usr/bin/codex", "resume"}
	var addTTY io.ReadWriter
	var execPath string
	var execArgs []string
	code := completeSSHBootstrap(args, &tty, func(got io.ReadWriter) error {
		addTTY = got
		return nil
	}, func(path string, argv, env []string) error {
		execPath = path
		execArgs = append([]string(nil), argv...)
		return nil
	})
	if code != 0 {
		t.Fatalf("completeSSHBootstrap code = %d, want 0", code)
	}
	if addTTY != &tty {
		t.Fatal("ssh-add did not receive the user terminal directly")
	}
	if execPath != args[0] || !reflect.DeepEqual(execArgs, args) {
		t.Fatalf("exec = %q %v, want %q %v", execPath, execArgs, args[0], args)
	}
	if message := tty.String(); message != "" {
		t.Fatalf("bootstrap repeated consent guidance: %q", message)
	}
}

func TestCompleteSSHBootstrapStopsWhenSSHAddFails(t *testing.T) {
	var tty bytes.Buffer
	execCalled := false
	code := completeSSHBootstrap([]string{"shield", "--", "codex"}, &tty, func(io.ReadWriter) error {
		return errors.New("test failure")
	}, func(string, []string, []string) error {
		execCalled = true
		return nil
	})
	if code != 1 || execCalled {
		t.Fatalf("code=%d execCalled=%v, want 1/false", code, execCalled)
	}
}

func TestUniquePathsPreservesFirstOccurrence(t *testing.T) {
	got := uniquePaths([]string{"/keys/a", "", "/keys/b", "/keys/a"})
	want := []string{"/keys/a", "/keys/b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uniquePaths = %v, want %v", got, want)
	}
}

func TestParseSSHBootstrapArgs(t *testing.T) {
	identities, command, err := parseSSHBootstrapArgs([]string{
		"--identity", "/home/test/.ssh/id_work",
		"--identity", "/home/test/.ssh/id_work",
		"--", "/usr/bin/codex", "resume",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/home/test/.ssh/id_work"}; !reflect.DeepEqual(identities, want) {
		t.Fatalf("identities = %v, want %v", identities, want)
	}
	if want := []string{"/usr/bin/codex", "resume"}; !reflect.DeepEqual(command, want) {
		t.Fatalf("command = %v, want %v", command, want)
	}
	for _, args := range [][]string{
		{"--identity", "relative", "--", "codex"},
		{"--identity", "/home/test/.ssh/id_work"},
		{"unexpected", "--", "codex"},
		{"--"},
	} {
		if _, _, err := parseSSHBootstrapArgs(args); err == nil {
			t.Fatalf("parseSSHBootstrapArgs(%v) unexpectedly succeeded", args)
		}
	}
}
