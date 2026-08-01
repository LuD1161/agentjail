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

func TestSystemdUserEnvironmentReconstructsExplicitValues(t *testing.T) {
	runtimeDir, cleanup := userRuntimeFixture(t)
	defer cleanup()

	env, err := systemdUserEnvironment([]string{
		"PATH=/usr/bin",
		"XDG_RUNTIME_DIR=/explicit/runtime",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/explicit/bus",
	}, os.Getuid(), runtimeDir)
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	if got, _ := environmentValue(env, "XDG_RUNTIME_DIR"); got != runtimeDir {
		t.Fatalf("XDG_RUNTIME_DIR = %q, want %q", got, runtimeDir)
	}
	if got, _ := environmentValue(env, "DBUS_SESSION_BUS_ADDRESS"); got != "unix:path="+filepath.Join(runtimeDir, "bus") {
		t.Fatalf("DBUS_SESSION_BUS_ADDRESS = %q, want trusted user bus", got)
	}
}

func TestSystemdUserEnvironmentReplacesExplicitEmptyValues(t *testing.T) {
	runtimeDir, cleanup := userRuntimeFixture(t)
	defer cleanup()

	env, err := systemdUserEnvironment([]string{"XDG_RUNTIME_DIR=", "DBUS_SESSION_BUS_ADDRESS="}, os.Getuid(), runtimeDir)
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	if got, _ := environmentValue(env, "XDG_RUNTIME_DIR"); got != runtimeDir {
		t.Fatalf("XDG_RUNTIME_DIR = %q, want %q", got, runtimeDir)
	}
}

func TestSystemdUserEnvironmentUsesExpectedRuntimeDir(t *testing.T) {
	runtimeDir, cleanup := userRuntimeFixture(t)
	defer cleanup()

	env, err := systemdUserEnvironment([]string{"XDG_RUNTIME_DIR=/untrusted/runtime"}, os.Getuid(), runtimeDir)
	if err != nil {
		t.Fatalf("systemdUserEnvironment: %v", err)
	}
	got, ok := environmentValue(env, "DBUS_SESSION_BUS_ADDRESS")
	want := "unix:path=" + filepath.Join(runtimeDir, "bus")
	if !ok || got != want {
		t.Fatalf("DBUS_SESSION_BUS_ADDRESS = %q, %v; want %q, true", got, ok, want)
	}
}

func TestSystemctlUsesTrustedAbsolutePath(t *testing.T) {
	if !filepath.IsAbs(systemctlPath) {
		t.Fatalf("systemctl path %q is not absolute", systemctlPath)
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
