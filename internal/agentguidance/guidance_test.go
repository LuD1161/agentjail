package agentguidance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuidanceContract(t *testing.T) {
	want := "This session runs inside AgentJail's OS-native safety sandbox, which governs host files and CLIs, MCP tools, credentials, and network access.\n" +
		"For required host file or CLI access, consult `agentjail proxy --help`; use MCP and credential tools normally so AgentJail can apply their approval flow, and stop if denied or rejected."
	if Guidance != want {
		t.Fatalf("Guidance = %q, want %q", Guidance, want)
	}
}

func TestReconcilePreservesUserContentAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AGENTS.md")
	original := []byte("# Personal instructions\n\nKeep this exact.\n")
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}

	changed, err := Reconcile(path)
	if err != nil || !changed {
		t.Fatalf("Reconcile() = (%v, %v), want changed", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), string(original)) || strings.Count(string(got), MarkerStart) != 1 {
		t.Fatalf("reconciled content did not preserve prefix or unique block:\n%s", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640", info.Mode().Perm())
	}

	changed, err = Remove(path)
	if err != nil || !changed {
		t.Fatalf("Remove() = (%v, %v), want changed", changed, err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("content after removal = %q, want %q", got, original)
	}
}

func TestReconcileRefreshesBlockExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	stale := "user\n\n" + MarkerStart + "\nstale\n" + MarkerEnd + "\n"
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, err := Reconcile(path)
	if err != nil || !changed {
		t.Fatalf("first Reconcile() = (%v, %v), want changed", changed, err)
	}
	changed, err = Reconcile(path)
	if err != nil || changed {
		t.Fatalf("second Reconcile() = (%v, %v), want unchanged", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got), MarkerStart) != 1 || !strings.Contains(string(got), Guidance) || strings.Contains(string(got), "stale") {
		t.Fatalf("managed block did not converge:\n%s", got)
	}
}

func TestReconcileMigratesLegacyTwoLineGuidance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	original := "user instructions\n"
	legacy := original + "\n" + Guidance + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Reconcile(path); err != nil || !changed {
		t.Fatalf("Reconcile() = (%v, %v), want migrated", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got), Guidance) != 1 || strings.Count(string(got), MarkerStart) != 1 {
		t.Fatalf("legacy guidance did not migrate to one managed block:\n%s", got)
	}
	if changed, err := Remove(path); err != nil || !changed {
		t.Fatalf("Remove() = (%v, %v), want removed", changed, err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("content after migrated removal = %q, want %q", got, original)
	}
}

func TestRemoveCleansLegacyTwoLineOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AGENTS.md")
	if err := os.WriteFile(path, []byte(Guidance+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Remove(path); err != nil || !changed {
		t.Fatalf("Remove() = (%v, %v), want removed", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("legacy-only file after removal = %q, want empty", got)
	}
}

func TestReconcileRejectsMalformedMarkersWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AGENTS.md")
	original := []byte("user\n" + MarkerStart + "\nunterminated\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Reconcile(path); err == nil {
		t.Fatal("Reconcile() error = nil, want malformed marker error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("malformed document changed: %q", got)
	}
}

func TestReconcileRejectsDuplicateBlocksWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AGENTS.md")
	block := MarkerStart + "\nold\n" + MarkerEnd + "\n"
	original := []byte(block + block)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Reconcile(path); err == nil {
		t.Fatal("Reconcile() error = nil, want duplicate block error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("duplicate-block document changed: %q", got)
	}
}

func TestReconcilePreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "shared.md")
	path := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(target, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("shared.md", path); err != nil {
		t.Fatal(err)
	}
	if _, err := Reconcile(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("Reconcile replaced the guidance symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), Guidance) {
		t.Fatalf("symlink target missing guidance: %s", got)
	}
}
