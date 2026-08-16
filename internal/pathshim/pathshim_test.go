package pathshim

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReassertRequiresPriorConsent(t *testing.T) {
	home := t.TempDir()
	shield := installTestShield(t, home)

	result, err := Reassert(home, shield, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied || AnyInstalled(home) {
		t.Fatal("reassert installed shims without prior consent")
	}
}

func TestReassertRestoresCompleteTargetSet(t *testing.T) {
	home := t.TempDir()
	shield := installTestShield(t, home)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(MarkerStart+"\n"+MarkerEnd+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Reassert(home, shield, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || !result.Restored || !Complete(home) {
		t.Fatalf("result = %+v, complete = %v", result, Complete(home))
	}
}

func TestRenderedTargetsAreValidShell(t *testing.T) {
	for _, target := range Targets() {
		t.Run(target.Command, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, target.Command)
			content := Render(target, filepath.Join(dir, "agentjail-shield"), dir, path)
			if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("invalid shell: %v\n%s", err, out)
			}
			for _, want := range []string{
				"command -v " + target.Command,
				"Running " + target.Command + " UNSHIELDED",
				`AGENTJAIL_REQUIRE_TUNNEL`,
				`exec "$LAUNCHER" run "$_tunnel_flag" -- ` + target.Command + ` "$@"`,
				`exec "$SHIELD" "$_tunnel_flag" -- "$REAL_`,
			} {
				if !strings.Contains(content, want) {
					t.Errorf("shim missing %q", want)
				}
			}
		})
	}
}

func TestRenderedShimCanRequireTunnel(t *testing.T) {
	t.Setenv("AGENTJAIL_REQUIRE_TUNNEL", "1")
	runRenderedCodexShim(t, []string{"exec", "test"})
}

func TestCodexBypassFlagKeepsOnlyRuleApprovalsInteractive(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "current bypass spelling",
			args: []string{"--dangerously-bypass-approvals-and-sandbox", "--dangerously-bypass-hook-trust"},
			want: append(codexAgentJailApprovalArgs(), "--dangerously-bypass-hook-trust"),
		},
		{
			name: "legacy yolo spelling",
			args: []string{"--yolo", "--search"},
			want: append(codexAgentJailApprovalArgs(), "--search"),
		},
		{
			name: "ordinary arguments pass through",
			args: []string{"--sandbox", "read-only"},
			want: []string{"--sandbox", "read-only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRenderedCodexShim(t, tt.args)
			if strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
				t.Fatalf("argv = %q, want %q", got, tt.want)
			}
		})
	}
}

func codexAgentJailApprovalArgs() []string {
	return []string{
		"--sandbox", "danger-full-access",
		"-c", "approval_policy={ granular = { sandbox_approval = false, rules = true, mcp_elicitations = false, request_permissions = false, skill_approval = false } }",
		"-c", `approvals_reviewer="user"`,
	}
}

func runRenderedCodexShim(t *testing.T, args []string) []string {
	t.Helper()
	root := t.TempDir()
	shimDir := filepath.Join(root, "shim")
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}

	capture := filepath.Join(root, "argv")
	route := filepath.Join(root, "route")
	shield := filepath.Join(root, "agentjail-shield")
	if err := os.WriteFile(shield, []byte("#!/bin/sh\nprintf 'shield\\n' > \"$CAPTURE_ROUTE\"\n[ \"$1\" = \"--\" ] || exit 64\nshift\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "agentjail")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf 'launcher:%s\\n' \"$2\" > \"$CAPTURE_ROUTE\"\n[ \"$1\" = run ] || exit 64\n{ [ \"$2\" = --tunnel ] || [ \"$2\" = --require-tunnel ]; } || exit 64\n[ \"$3\" = -- ] || exit 64\n[ \"$4\" = codex ] || exit 64\nshift 4\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	realCodex := filepath.Join(realDir, "codex")
	if err := os.WriteFile(realCodex, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	shim := filepath.Join(shimDir, "codex")
	content := Render(Target{Command: "codex", DisplayName: "Codex"}, shield, shimDir, shim)
	if err := os.WriteFile(shim, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(shim, args...)
	cmd.Env = append(os.Environ(),
		"CAPTURE_ARGS="+capture,
		"CAPTURE_ROUTE="+route,
		"PATH="+shimDir+":"+realDir+":/usr/bin:/bin",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run shim: %v\n%s", err, out)
	}
	rawRoute, err := os.ReadFile(route)
	if err != nil {
		t.Fatal(err)
	}
	wantRoute := "launcher:--tunnel"
	if os.Getenv("AGENTJAIL_REQUIRE_TUNNEL") == "1" {
		wantRoute = "launcher:--require-tunnel"
	}
	if strings.TrimSpace(string(rawRoute)) != wantRoute {
		t.Fatalf("shim route = %q, want %q", rawRoute, wantRoute)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func installTestShield(t *testing.T, home string) string {
	t.Helper()
	binDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shield := filepath.Join(binDir, "agentjail-shield")
	if err := os.WriteFile(shield, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return shield
}
