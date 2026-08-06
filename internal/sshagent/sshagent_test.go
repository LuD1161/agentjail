package sshagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	tests := []struct {
		name            string
		sockPath        string
		keyPaths        []string
		runSSHAdd       func(ctx context.Context) (int, error)
		wantReadiness   Readiness
		wantNeedsRemedy bool
	}{
		{
			name:            "exit 0 with keys on disk is ready",
			sockPath:        "/tmp/agent.sock",
			keyPaths:        []string{"/home/u/.ssh/id_ed25519"},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantReadiness:   ReadinessReady,
			wantNeedsRemedy: false,
		},
		{
			name:            "exit 1 with keys on disk is no keys, needs remediation",
			sockPath:        "/tmp/agent.sock",
			keyPaths:        []string{"/home/u/.ssh/id_ed25519"},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 1, nil },
			wantReadiness:   ReadinessNoKeys,
			wantNeedsRemedy: true,
		},
		{
			name:            "exit 2 with keys on disk is no agent, needs remediation",
			sockPath:        "/tmp/agent.sock",
			keyPaths:        []string{"/home/u/.ssh/id_ed25519"},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 2, nil },
			wantReadiness:   ReadinessNoAgent,
			wantNeedsRemedy: true,
		},
		{
			name:     "empty sock path with keys on disk is no agent, RunSSHAdd not required",
			sockPath: "",
			keyPaths: []string{"/home/u/.ssh/id_ed25519"},
			runSSHAdd: func(ctx context.Context) (int, error) {
				t.Fatal("RunSSHAdd should not be called when SSH_AUTH_SOCK is empty")
				return 0, nil
			},
			wantReadiness:   ReadinessNoAgent,
			wantNeedsRemedy: true,
		},
		{
			name:            "no keys on disk never needs remediation, even when ready",
			sockPath:        "/tmp/agent.sock",
			keyPaths:        nil,
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantReadiness:   ReadinessReady,
			wantNeedsRemedy: false,
		},
		{
			name:            "no keys on disk never needs remediation, no agent",
			sockPath:        "",
			keyPaths:        nil,
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantReadiness:   ReadinessNoAgent,
			wantNeedsRemedy: false,
		},
		{
			name:     "RunSSHAdd error is treated as no agent, not ready",
			sockPath: "/tmp/agent.sock",
			keyPaths: []string{"/home/u/.ssh/id_ed25519"},
			runSSHAdd: func(ctx context.Context) (int, error) {
				return 0, errors.New("exec: \"ssh-add\": executable file not found in $PATH")
			},
			wantReadiness:   ReadinessNoAgent,
			wantNeedsRemedy: true,
		},
		{
			name:     "RunSSHAdd context timeout is treated as no agent, not ready",
			sockPath: "/tmp/agent.sock",
			keyPaths: []string{"/home/u/.ssh/id_ed25519"},
			runSSHAdd: func(ctx context.Context) (int, error) {
				return 0, context.DeadlineExceeded
			},
			wantReadiness:   ReadinessNoAgent,
			wantNeedsRemedy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Prober{
				RunSSHAdd: tt.runSSHAdd,
				FindKeyFiles: func() KeyFiles {
					if len(tt.keyPaths) == 0 {
						return KeyFiles{State: KeyStateAbsent}
					}
					return KeyFiles{State: KeyStatePresent, Paths: tt.keyPaths}
				},
				Getenv: func(name string) string {
					if name == "SSH_AUTH_SOCK" {
						return tt.sockPath
					}
					return ""
				},
			}
			got := p.Probe(context.Background())
			if got.Readiness != tt.wantReadiness {
				t.Errorf("Readiness = %v, want %v", got.Readiness, tt.wantReadiness)
			}
			if got.NeedsRemediation() != tt.wantNeedsRemedy {
				t.Errorf("NeedsRemediation() = %v, want %v", got.NeedsRemediation(), tt.wantNeedsRemedy)
			}
			if got.SockPath != tt.sockPath {
				t.Errorf("SockPath = %q, want %q", got.SockPath, tt.sockPath)
			}
			if len(got.KeyPaths) != len(tt.keyPaths) {
				t.Errorf("KeyPaths = %v, want %v", got.KeyPaths, tt.keyPaths)
			}
		})
	}
}

func TestProbePreservesShieldedDelegationAndUnknownKeyState(t *testing.T) {
	p := &Prober{
		FindKeyFiles: func() KeyFiles { return KeyFiles{State: KeyStateUnknown} },
		RunSSHAdd: func(ctx context.Context) (int, error) {
			return 0, nil
		},
		Getenv: func(name string) string {
			switch name {
			case "AGENTJAIL_SHIELDED":
				return "1"
			case DelegationEnv:
				return "1"
			case "SSH_AUTH_SOCK":
				return "/tmp/agent.sock"
			default:
				return ""
			}
		},
	}

	got := p.Probe(context.Background())
	if got.Execution != ExecutionShielded {
		t.Errorf("Execution = %v, want ExecutionShielded", got.Execution)
	}
	if got.Delegation != DelegationRequested {
		t.Errorf("Delegation = %v, want DelegationRequested", got.Delegation)
	}
	if got.KeyState != KeyStateUnknown {
		t.Errorf("KeyState = %v, want KeyStateUnknown", got.KeyState)
	}
	if got.NeedsRemediation() {
		t.Error("NeedsRemediation() = true for unknown key state, want false")
	}
}

func TestProbeScansPinnedConfigWithoutSocket(t *testing.T) {
	const home = "/home/u"
	p := &Prober{
		FindKeyFiles: func() KeyFiles { return KeyFiles{State: KeyStateUnknown} },
		Getenv: func(name string) string {
			if name == "HOME" {
				return home
			}
			return ""
		},
		ReadSSHConfig: func() string { return pinnedConfig },
		PathExists: func(path string) bool {
			return path == filepath.Join(home, ".ssh", "id_ed25519")
		},
	}

	got := p.Probe(context.Background())
	if got.Readiness != ReadinessNoAgent {
		t.Errorf("Readiness = %v, want ReadinessNoAgent", got.Readiness)
	}
	if !got.PinnedIdentity() {
		t.Error("PinnedIdentity() = false, want true when SSH_AUTH_SOCK is unset")
	}
}

func TestRemediation(t *testing.T) {
	t.Run("darwin single id_ed25519", func(t *testing.T) {
		s := Status{
			Readiness: ReadinessNoKeys,
			KeyState:  KeyStatePresent,
			KeyPaths:  []string{"/home/u/.ssh/id_ed25519"},
		}
		got := s.Remediation("darwin")
		if !strings.Contains(got, "--apple-use-keychain") {
			t.Errorf("Remediation(darwin) = %q, want to contain --apple-use-keychain", got)
		}
		if !strings.Contains(got, "id_ed25519") {
			t.Errorf("Remediation(darwin) = %q, want to contain id_ed25519", got)
		}
	})

	t.Run("linux single key", func(t *testing.T) {
		s := Status{
			Readiness: ReadinessNoAgent,
			KeyState:  KeyStatePresent,
			KeyPaths:  []string{"/home/u/.ssh/id_ed25519"},
		}
		got := s.Remediation("linux")
		if !strings.Contains(got, "ssh-agent") {
			t.Errorf("Remediation(linux) = %q, want to contain ssh-agent", got)
		}
		if !strings.Contains(got, "ssh-add") {
			t.Errorf("Remediation(linux) = %q, want to contain ssh-add", got)
		}
	})

	t.Run("multiple keys without id_ed25519 falls back to placeholder", func(t *testing.T) {
		s := Status{
			Readiness: ReadinessNoKeys,
			KeyState:  KeyStatePresent,
			KeyPaths:  []string{"/home/u/.ssh/id_rsa", "/home/u/.ssh/id_ecdsa"},
		}
		got := s.Remediation("linux")
		if !strings.Contains(got, "<your-key>") {
			t.Errorf("Remediation(linux) = %q, want to contain <your-key>", got)
		}
	})

	t.Run("multiple keys with id_ed25519 prefers it", func(t *testing.T) {
		s := Status{
			Readiness: ReadinessNoKeys,
			KeyState:  KeyStatePresent,
			KeyPaths:  []string{"/home/u/.ssh/id_rsa", "/home/u/.ssh/id_ed25519"},
		}
		got := s.Remediation("darwin")
		if !strings.Contains(got, "id_ed25519") {
			t.Errorf("Remediation(darwin) = %q, want to contain id_ed25519", got)
		}
	})

	t.Run("no remediation needed returns empty string", func(t *testing.T) {
		s := Status{
			Readiness: ReadinessReady,
			KeyState:  KeyStatePresent,
			KeyPaths:  []string{"/home/u/.ssh/id_ed25519"},
		}
		if got := s.Remediation("darwin"); got != "" {
			t.Errorf("Remediation() = %q, want empty string when not needed", got)
		}
	})
}

// --- Pinned IdentityFile blind spot (Task B) ---

const pinnedConfig = `Host github.com
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519
`

const pinnedDeployConfig = `Host deploy
    IdentitiesOnly yes
    IdentityFile ~/.ssh/github_deploy
`

const notPinnedConfig = `Host github.com
    IdentityFile ~/.ssh/id_ed25519
`

const commentedConfig = `Host github.com
    #IdentitiesOnly yes
    # IdentityFile ~/.ssh/id_ed25519
`

const outsideSSHDirConfig = `Host internal
    IdentitiesOnly yes
    IdentityFile /etc/ssh/x
`

func TestProbePinnedIdentity(t *testing.T) {
	const home = "/home/u"

	tests := []struct {
		name            string
		config          string
		pathExists      func(path string) bool
		runSSHAdd       func(ctx context.Context) (int, error)
		wantPinnedPaths []string
		wantPinnedBlind bool
	}{
		{
			name:   "pinned config with existing file and ready agent is a blind spot",
			config: pinnedConfig,
			pathExists: func(path string) bool {
				return path == filepath.Join(home, ".ssh", "id_ed25519")
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: []string{filepath.Join(home, ".ssh", "id_ed25519")},
			wantPinnedBlind: true,
		},
		{
			name:   "pinned config with ENOENT file is excluded",
			config: pinnedConfig,
			pathExists: func(path string) bool {
				return false // simulates a plain os.Stat ENOENT
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: nil,
			wantPinnedBlind: false,
		},
		{
			name:   "pinned config with permission-denied file is included (under-shield case)",
			config: pinnedConfig,
			pathExists: func(path string) bool {
				return true // simulates the fs.ErrPermission branch of the default PathExists
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: []string{filepath.Join(home, ".ssh", "id_ed25519")},
			wantPinnedBlind: true,
		},
		{
			name:   "IdentityFile without IdentitiesOnly yes is not pinned",
			config: notPinnedConfig,
			pathExists: func(path string) bool {
				return true
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: nil,
			wantPinnedBlind: false,
		},
		{
			name:   "commented out IdentitiesOnly and IdentityFile lines are ignored",
			config: commentedConfig,
			pathExists: func(path string) bool {
				return true
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: nil,
			wantPinnedBlind: false,
		},
		{
			name:   "deploy-key path not matching id_* glob is still pinned",
			config: pinnedDeployConfig,
			pathExists: func(path string) bool {
				return path == filepath.Join(home, ".ssh", "github_deploy")
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: []string{filepath.Join(home, ".ssh", "github_deploy")},
			wantPinnedBlind: true,
		},
		{
			name:   "IdentityFile outside ~/.ssh is excluded",
			config: outsideSSHDirConfig,
			pathExists: func(path string) bool {
				return true
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 0, nil },
			wantPinnedPaths: nil,
			wantPinnedBlind: false,
		},
		{
			name:   "pinned config but agent not ready is not a blind spot",
			config: pinnedConfig,
			pathExists: func(path string) bool {
				return true
			},
			runSSHAdd:       func(ctx context.Context) (int, error) { return 1, nil },
			wantPinnedPaths: []string{filepath.Join(home, ".ssh", "id_ed25519")},
			wantPinnedBlind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Prober{
				RunSSHAdd: tt.runSSHAdd,
				FindKeyFiles: func() KeyFiles {
					return KeyFiles{State: KeyStateAbsent}
				},
				Getenv: func(name string) string {
					if name == "SSH_AUTH_SOCK" {
						return "/tmp/agent.sock"
					}
					if name == "HOME" {
						return home
					}
					return ""
				},
				ReadSSHConfig: func() string { return tt.config },
				PathExists:    tt.pathExists,
			}
			got := p.Probe(context.Background())

			if len(got.PinnedIdentityPaths) != len(tt.wantPinnedPaths) {
				t.Fatalf("PinnedIdentityPaths = %v, want %v", got.PinnedIdentityPaths, tt.wantPinnedPaths)
			}
			for i, want := range tt.wantPinnedPaths {
				if got.PinnedIdentityPaths[i] != want {
					t.Errorf("PinnedIdentityPaths[%d] = %q, want %q", i, got.PinnedIdentityPaths[i], want)
				}
			}
			if got.PinnedIdentity() != (len(tt.wantPinnedPaths) > 0) {
				t.Errorf("PinnedIdentity() = %v, want %v", got.PinnedIdentity(), len(tt.wantPinnedPaths) > 0)
			}
			if got.PinnedBlindSpot() != tt.wantPinnedBlind {
				t.Errorf("PinnedBlindSpot() = %v, want %v", got.PinnedBlindSpot(), tt.wantPinnedBlind)
			}
		})
	}
}

func TestPinnedRemediation(t *testing.T) {
	t.Run("blind spot returns agent-routing guidance", func(t *testing.T) {
		s := Status{
			Readiness:           ReadinessReady,
			PinnedIdentityPaths: []string{"/home/u/.ssh/id_ed25519"},
		}
		got := s.PinnedRemediation("linux")
		if !strings.Contains(got, "IdentityFile=none") {
			t.Errorf("PinnedRemediation() = %q, want to contain IdentityFile=none", got)
		}
		// IdentitiesOnly=no is the decisive option (an agent key that differs
		// from the pinned one is otherwise never offered); assert it explicitly
		// so a regression cannot slip through on the IdentityFile=none check.
		if !strings.Contains(got, "IdentitiesOnly=no") {
			t.Errorf("PinnedRemediation() = %q, want to contain IdentitiesOnly=no", got)
		}
		if strings.Contains(strings.ToLower(got), "grant") {
			t.Errorf("PinnedRemediation() = %q, must never suggest granting the key file", got)
		}
		if strings.Contains(strings.ToLower(got), "chmod") {
			t.Errorf("PinnedRemediation() = %q, must never suggest chmod-ing the key file", got)
		}
	})

	t.Run("not a blind spot returns empty string", func(t *testing.T) {
		s := Status{
			Readiness:           ReadinessNoKeys,
			PinnedIdentityPaths: []string{"/home/u/.ssh/id_ed25519"},
		}
		if got := s.PinnedRemediation("linux"); got != "" {
			t.Errorf("PinnedRemediation() = %q, want empty string when not a blind spot", got)
		}
	})

	t.Run("no pinned identity returns empty string even when ready", func(t *testing.T) {
		s := Status{Readiness: ReadinessReady}
		if got := s.PinnedRemediation("darwin"); got != "" {
			t.Errorf("PinnedRemediation() = %q, want empty string when nothing pinned", got)
		}
	})
}

func TestPathExistsRealDefaultImpl(t *testing.T) {
	t.Run("existing file returns true", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "exists")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if !pathExistsReal(f) {
			t.Errorf("pathExistsReal(%q) = false, want true", f)
		}
	})

	t.Run("non-existent path returns false", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "does-not-exist")
		if pathExistsReal(f) {
			t.Errorf("pathExistsReal(%q) = true, want false", f)
		}
	})

	t.Run("permission-denied path returns true", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("chmod-based permission denial is not meaningful on windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("running as root bypasses permission checks; cannot exercise EPERM")
		}
		dir := t.TempDir()
		blocked := filepath.Join(dir, "blocked")
		if err := os.Mkdir(blocked, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		target := filepath.Join(blocked, "id_ed25519")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		defer os.Chmod(blocked, 0o755) // restore so TempDir cleanup can remove it

		if !pathExistsReal(target) {
			t.Errorf("pathExistsReal(%q) = false, want true (permission-denied should still count as existing)", target)
		}
	})
}
