package shieldapp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Guards the launch posture: an unopenable store must be reported, never
// swallowed. See ADR 0089-record-shield-launches.

// TestOpenShieldAuditHappyPath pins that a writable state dir still yields a
// real emitter -- the fix must not cost the happy path.
func TestOpenShieldAuditHappyPath(t *testing.T) {
	dir := t.TempDir()
	st, err := openShieldAudit(dir)
	if err != nil {
		t.Fatalf("openShieldAudit(%q) = %v; want a store", dir, err)
	}
	defer st.Close()
	if _, err := os.Stat(shieldDBPath(dir)); err != nil {
		t.Errorf("db not created at %s: %v", shieldDBPath(dir), err)
	}
	if _, err := os.Stat(filepath.Join(dir, unrecordedMarkerName)); !os.IsNotExist(err) {
		t.Errorf("marker written on the happy path; want none")
	}
}

// TestOpenShieldAuditUnopenable pins that a directory squatting on the DB path
// surfaces an error rather than a silent NopEmitter.
func TestOpenShieldAuditUnopenable(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(shieldDBPath(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := openShieldAudit(dir)
	if err == nil {
		st.Close()
		t.Fatal("openShieldAudit succeeded with a directory at the DB path; want error")
	}
}

// TestOpenShieldAuditReadOnlyParent covers the other real failure shape: the
// state dir exists but cannot be written.
func TestOpenShieldAuditReadOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	parent := t.TempDir()
	stateDir := filepath.Join(parent, ".agentjail")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

	st, err := openShieldAudit(stateDir)
	if err == nil {
		st.Close()
		t.Fatal("openShieldAudit succeeded under a read-only state dir; want error")
	}
}

// TestUnrecordableWarningIsLoud pins that the banner names the store, says the
// sandbox still applies, and says the session is unrecorded. The launch
// proceeds, so the text is the whole of the user-facing signal.
func TestUnrecordableWarningIsLoud(t *testing.T) {
	msg := unrecordableWarning("/home/u/.agentjail/agentjail.db", errors.New("disk full"))
	for _, want := range []string{
		"WARNING",
		"/home/u/.agentjail/agentjail.db",
		"disk full",
		"sandbox still applies",
		"NOT be recorded",
		"agentjail doctor",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning missing %q; got:\n%s", want, msg)
		}
	}
}

// TestMarkShieldUnrecorded pins the marker doctor will read to tell "the shield
// could not write" apart from "the shield never ran".
func TestMarkShieldUnrecorded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".agentjail")
	markShieldUnrecorded(dir, errors.New("store: ping: corrupt"))

	b, err := os.ReadFile(filepath.Join(dir, unrecordedMarkerName))
	if err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	var m unrecordedMarker
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("marker is not valid JSON: %v (%q)", err, b)
	}
	if m.TS == "" || m.PID != os.Getpid() {
		t.Errorf("marker = %+v; want ts set and pid %d", m, os.Getpid())
	}
	if !strings.Contains(m.Reason, "corrupt") {
		t.Errorf("marker reason = %q; want the open error", m.Reason)
	}
}

// TestMarkShieldUnrecordedNeverPanics pins that the marker degrades quietly
// when its own write fails -- it is a diagnostic, never a launch blocker.
func TestMarkShieldUnrecordedNeverPanics(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	markShieldUnrecorded(filepath.Join(file, "nested"), errors.New("boom"))
}

// TestShieldStateDirNoTmpFallback pins that a missing $HOME errors instead of
// silently relocating the store somewhere no reader looks.
func TestShieldStateDirNoTmpFallback(t *testing.T) {
	t.Setenv("HOME", "")
	dir, err := shieldStateDir()
	if err == nil && !strings.HasSuffix(dir, ".agentjail") {
		t.Errorf("shieldStateDir() = %q, %v; want an error or a ~/.agentjail path", dir, err)
	}
	if err == nil {
		return // some platforms resolve HOME from the user database
	}
	if dir != "" {
		t.Errorf("shieldStateDir() returned %q alongside an error; want empty", dir)
	}
}
