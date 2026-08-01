//go:build linux

package selfupdate

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSystemdUserEnvironmentDerivesMissingValues(t *testing.T) {
	runtimeDir, cleanup := userRuntimeFixture(t)
	defer cleanup()

	env, err := systemdUserEnvironment([]string{"PATH=/usr/bin"}, os.Getuid(), runtimeDir)
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	want := map[string]string{
		"XDG_RUNTIME_DIR":          runtimeDir,
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=" + filepath.Join(runtimeDir, "bus"),
	}
	for name, value := range want {
		got, ok := environmentValue(env, name)
		if !ok || got != value {
			t.Errorf("%s = %q, %v; want %q, true", name, got, ok, value)
		}
	}
}

func TestSystemdUserEnvironmentPreservesExplicitValues(t *testing.T) {
	original := []string{
		"PATH=/usr/bin",
		"XDG_RUNTIME_DIR=/explicit/runtime",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/explicit/bus",
	}
	env, err := systemdUserEnvironment(original, os.Getuid(), "/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	if strings.Join(env, "\x00") != strings.Join(original, "\x00") {
		t.Fatalf("environment changed: got %q, want %q", env, original)
	}
}

func TestSystemdUserEnvironmentPreservesExplicitEmptyValues(t *testing.T) {
	original := []string{"XDG_RUNTIME_DIR=", "DBUS_SESSION_BUS_ADDRESS="}
	env, err := systemdUserEnvironment(original, os.Getuid(), "/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	if strings.Join(env, "\x00") != strings.Join(original, "\x00") {
		t.Fatalf("environment changed: got %q, want %q", env, original)
	}
}

func TestSystemdUserEnvironmentDerivesBusFromExplicitRuntimeDir(t *testing.T) {
	runtimeDir, cleanup := userRuntimeFixture(t)
	defer cleanup()

	env, err := systemdUserEnvironment([]string{"XDG_RUNTIME_DIR=" + runtimeDir}, os.Getuid(), "/unused")
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	got, ok := environmentValue(env, "DBUS_SESSION_BUS_ADDRESS")
	want := "unix:path=" + filepath.Join(runtimeDir, "bus")
	if !ok || got != want {
		t.Fatalf("DBUS_SESSION_BUS_ADDRESS = %q, %v; want %q, true", got, ok, want)
	}
}

func TestSystemdUserEnvironmentPreservesExplicitBusAddress(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	originalBus := "unix:path=/explicit/bus"

	env, err := systemdUserEnvironment([]string{"DBUS_SESSION_BUS_ADDRESS=" + originalBus}, os.Getuid(), runtimeDir)
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	gotBus, ok := environmentValue(env, "DBUS_SESSION_BUS_ADDRESS")
	if !ok || gotBus != originalBus {
		t.Fatalf("DBUS_SESSION_BUS_ADDRESS = %q, %v; want %q, true", gotBus, ok, originalBus)
	}
	gotRuntime, ok := environmentValue(env, "XDG_RUNTIME_DIR")
	if !ok || gotRuntime != runtimeDir {
		t.Fatalf("XDG_RUNTIME_DIR = %q, %v; want %q, true", gotRuntime, ok, runtimeDir)
	}
}

func TestSystemdUserEnvironmentRejectsUnsafeInferredRuntimeDir(t *testing.T) {
	tests := []struct {
		name string
		set  func(t *testing.T) string
		uid  int
		want string
	}{
		{
			name: "not directory",
			set: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "runtime")
				if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			uid:  os.Getuid(),
			want: "is not a directory",
		},
		{
			name: "permissive directory",
			set: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "runtime")
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
				return path
			},
			uid:  os.Getuid(),
			want: "permits group or other access",
		},
		{
			name: "wrong owner",
			set: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "runtime")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				return path
			},
			uid:  os.Getuid() + 1,
			want: "want " + strconv.Itoa(os.Getuid()+1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := systemdUserEnvironment(nil, tc.uid, tc.set(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestSystemdUserEnvironmentRejectsNonSocketBus(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "bus"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := systemdUserEnvironment(nil, os.Getuid(), runtimeDir)
	if err == nil || !strings.Contains(err.Error(), "is not a socket") {
		t.Fatalf("error = %v, want non-socket error", err)
	}
}

func userRuntimeFixture(t *testing.T) (string, func()) {
	t.Helper()
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(runtimeDir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	return runtimeDir, func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close user bus fixture: %v", err)
		}
	}
}
