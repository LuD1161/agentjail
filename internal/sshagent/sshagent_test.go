package sshagent

import (
	"context"
	"errors"
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
				RunSSHAdd:    tt.runSSHAdd,
				ListKeyFiles: func() []string { return tt.keyPaths },
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

func TestRemediation(t *testing.T) {
	t.Run("darwin single id_ed25519", func(t *testing.T) {
		s := Status{
			Readiness:  ReadinessNoKeys,
			KeysOnDisk: true,
			KeyPaths:   []string{"/home/u/.ssh/id_ed25519"},
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
			Readiness:  ReadinessNoAgent,
			KeysOnDisk: true,
			KeyPaths:   []string{"/home/u/.ssh/id_ed25519"},
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
			Readiness:  ReadinessNoKeys,
			KeysOnDisk: true,
			KeyPaths:   []string{"/home/u/.ssh/id_rsa", "/home/u/.ssh/id_ecdsa"},
		}
		got := s.Remediation("linux")
		if !strings.Contains(got, "<your-key>") {
			t.Errorf("Remediation(linux) = %q, want to contain <your-key>", got)
		}
	})

	t.Run("multiple keys with id_ed25519 prefers it", func(t *testing.T) {
		s := Status{
			Readiness:  ReadinessNoKeys,
			KeysOnDisk: true,
			KeyPaths:   []string{"/home/u/.ssh/id_rsa", "/home/u/.ssh/id_ed25519"},
		}
		got := s.Remediation("darwin")
		if !strings.Contains(got, "id_ed25519") {
			t.Errorf("Remediation(darwin) = %q, want to contain id_ed25519", got)
		}
	})

	t.Run("no remediation needed returns empty string", func(t *testing.T) {
		s := Status{
			Readiness:  ReadinessReady,
			KeysOnDisk: true,
			KeyPaths:   []string{"/home/u/.ssh/id_ed25519"},
		}
		if got := s.Remediation("darwin"); got != "" {
			t.Errorf("Remediation() = %q, want empty string when not needed", got)
		}
	})
}
