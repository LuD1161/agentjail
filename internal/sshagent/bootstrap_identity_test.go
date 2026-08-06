package sshagent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBootstrapIdentityResolverUsesCurrentRemoteSSHConfig(t *testing.T) {
	home := "/home/test"
	workKey := home + "/.ssh/id_work"
	otherKey := home + "/.ssh/id_other"
	resolver := &BootstrapIdentityResolver{
		RunCommand: func(_ context.Context, _ string, name string, args ...string) (string, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case "git branch --show-current":
				return "main\n", nil
			case "git config --get branch.main.pushRemote":
				return "work\n", nil
			case "git remote get-url --push -- work":
				return "git@github-work:company/repository.git\n", nil
			case "ssh -G -l git -- github-work":
				return "hostname github.com\nidentityfile ~/.ssh/id_work\nidentityfile ~/.ssh/missing\n", nil
			default:
				return "", errors.New("unexpected command: " + command)
			}
		},
		PathExists: func(path string) bool { return path == workKey || path == otherKey },
	}

	got := resolver.Resolve(context.Background(), "/repo", home, []string{otherKey, workKey})
	want := IdentitySelection{Host: "github-work", Paths: []string{workKey}, Source: IdentitySelectionSSHConfig}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v, want %#v", got, want)
	}
}

func TestBootstrapIdentityResolverReturnsOrderedConfigAmbiguity(t *testing.T) {
	home := "/home/test"
	personal := home + "/.ssh/id_personal"
	work := home + "/.ssh/id_work"
	resolver := &BootstrapIdentityResolver{
		RunCommand: func(_ context.Context, _ string, name string, args ...string) (string, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case "git branch --show-current":
				return "main\n", nil
			case "git config --get branch.main.remote":
				return "origin\n", nil
			case "git remote get-url --push -- origin":
				return "ssh://git@github.com:22/company/repository.git\n", nil
			case "ssh -G -l git -p 22 -- github.com":
				return "identityfile %d/.ssh/id_personal\nidentityfile %d/.ssh/id_work\nidentityfile %d/.ssh/id_personal\n", nil
			default:
				return "", errors.New("unexpected command: " + command)
			}
		},
		PathExists: func(path string) bool { return path == personal || path == work },
	}

	got := resolver.Resolve(context.Background(), "/repo", home, nil)
	want := IdentitySelection{Host: "github.com", Paths: []string{personal, work}, Source: IdentitySelectionSSHConfig}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v, want %#v", got, want)
	}
}

func TestBootstrapIdentityResolverFallsBackWithoutSSHRemote(t *testing.T) {
	home := "/home/test"
	discovered := []string{home + "/.ssh/id_ed25519", home + "/.ssh/id_rsa", home + "/.ssh/id_ed25519"}
	resolver := &BootstrapIdentityResolver{
		RunCommand: func(_ context.Context, _ string, name string, args ...string) (string, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case "git branch --show-current":
				return "main\n", nil
			case "git config --get branch.main.remote":
				return "origin\n", nil
			case "git remote get-url --push -- origin":
				return "https://github.com/company/repository.git\n", nil
			default:
				return "", errors.New("unexpected command: " + command)
			}
		},
		PathExists: func(string) bool { return true },
	}

	got := resolver.Resolve(context.Background(), "/repo", home, discovered)
	want := IdentitySelection{Paths: discovered[:2], Source: IdentitySelectionDiscovered}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v, want %#v", got, want)
	}
}

func TestParseSSHRemote(t *testing.T) {
	tests := []struct {
		raw  string
		want sshDestination
		ok   bool
	}{
		{raw: "git@github-work:company/repository.git", want: sshDestination{Host: "github-work", User: "git"}, ok: true},
		{raw: "ssh://git@example.com:2222/company/repository.git", want: sshDestination{Host: "example.com", User: "git", Port: "2222"}, ok: true},
		{raw: "git@[::1]:repository.git", want: sshDestination{Host: "::1", User: "git"}, ok: true},
		{raw: "https://github.com/company/repository.git"},
		{raw: "/local/repository.git"},
		{raw: "-oProxyCommand=bad:repository.git"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, ok := parseSSHRemote(tt.raw)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("parseSSHRemote(%q) = %#v/%v, want %#v/%v", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}
