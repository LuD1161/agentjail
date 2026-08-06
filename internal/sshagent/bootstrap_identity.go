package sshagent

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// IdentitySelectionSource records why bootstrap identity candidates were chosen.
type IdentitySelectionSource int

const (
	IdentitySelectionDiscovered IdentitySelectionSource = iota
	IdentitySelectionSSHConfig
)

// IdentitySelection is the ordered set of private-key paths bootstrap may load.
type IdentitySelection struct {
	Host   string
	Paths  []string
	Source IdentitySelectionSource
}

// BootstrapIdentityResolver resolves a Git remote through the user's effective
// OpenSSH configuration. See ADR 0126-session-ssh-bootstrap.
type BootstrapIdentityResolver struct {
	RunCommand func(ctx context.Context, dir, name string, args ...string) (string, error)
	PathExists func(path string) bool
}

// DefaultBootstrapIdentityResolver returns a resolver backed by Git, OpenSSH,
// and the local filesystem.
func DefaultBootstrapIdentityResolver() *BootstrapIdentityResolver {
	return &BootstrapIdentityResolver{
		RunCommand: runBootstrapIdentityCommand,
		PathExists: pathExistsReal,
	}
}

// Resolve prefers identities selected by ssh_config for the current Git
// remote, then falls back to the locally discovered identities.
func (r *BootstrapIdentityResolver) Resolve(ctx context.Context, cwd, home string, discovered []string) IdentitySelection {
	fallback := IdentitySelection{Paths: uniqueIdentityPaths(discovered), Source: IdentitySelectionDiscovered}
	if r == nil || r.RunCommand == nil || r.PathExists == nil || cwd == "" || home == "" {
		return fallback
	}

	destination, ok := r.gitSSHDestination(ctx, cwd)
	if !ok {
		return fallback
	}
	effective, err := r.effectiveIdentityFiles(ctx, cwd, home, destination)
	if err != nil || len(effective) == 0 {
		fallback.Host = destination.Host
		return fallback
	}
	return IdentitySelection{
		Host:   destination.Host,
		Paths:  effective,
		Source: IdentitySelectionSSHConfig,
	}
}

type sshDestination struct {
	Host string
	User string
	Port string
}

func (r *BootstrapIdentityResolver) gitSSHDestination(ctx context.Context, cwd string) (sshDestination, bool) {
	remote := "origin"
	branch := ""
	if output, err := r.RunCommand(ctx, cwd, "git", "branch", "--show-current"); err == nil {
		branch = strings.TrimSpace(output)
	}
	configKeys := make([]string, 0, 3)
	if branch != "" {
		configKeys = append(configKeys, "branch."+branch+".pushRemote")
	}
	configKeys = append(configKeys, "remote.pushDefault")
	if branch != "" {
		configKeys = append(configKeys, "branch."+branch+".remote")
	}
	for _, key := range configKeys {
		configured, err := r.RunCommand(ctx, cwd, "git", "config", "--get", key)
		if err != nil {
			continue
		}
		configured = strings.TrimSpace(configured)
		if configured != "" && configured != "." {
			remote = configured
			break
		}
	}

	remoteURL, err := r.RunCommand(ctx, cwd, "git", "remote", "get-url", "--push", "--", remote)
	if err != nil && remote != "origin" {
		remoteURL, err = r.RunCommand(ctx, cwd, "git", "remote", "get-url", "--push", "--", "origin")
	}
	if err != nil {
		return sshDestination{}, false
	}
	return parseSSHRemote(strings.TrimSpace(remoteURL))
}

func (r *BootstrapIdentityResolver) effectiveIdentityFiles(ctx context.Context, cwd, home string, destination sshDestination) ([]string, error) {
	args := []string{"-G"}
	if destination.User != "" {
		args = append(args, "-l", destination.User)
	}
	if destination.Port != "" {
		args = append(args, "-p", destination.Port)
	}
	args = append(args, "--", destination.Host)
	output, err := r.RunCommand(ctx, cwd, "ssh", args...)
	if err != nil {
		return nil, err
	}

	sshDir := filepath.Join(home, ".ssh")
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		keyword, value, ok := splitSSHConfigLine(line)
		if !ok || !strings.EqualFold(keyword, "identityfile") || strings.EqualFold(value, "none") {
			continue
		}
		value = strings.ReplaceAll(value, "%d", home)
		path := filepath.Clean(expandHomePath(value, home))
		if !filepath.IsAbs(path) || !underDir(path, sshDir) || !r.PathExists(path) {
			continue
		}
		paths = append(paths, path)
	}
	return uniqueIdentityPaths(paths), nil
}

func parseSSHRemote(raw string) (sshDestination, bool) {
	if raw == "" {
		return sshDestination{}, false
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "ssh" && parsed.Scheme != "git+ssh") || parsed.Hostname() == "" {
			return sshDestination{}, false
		}
		destination := sshDestination{Host: parsed.Hostname(), Port: parsed.Port()}
		if parsed.User != nil {
			destination.User = parsed.User.Username()
		}
		return validSSHDestination(destination)
	}

	address := raw
	user := ""
	if at := strings.LastIndex(address, "@"); at >= 0 {
		user = address[:at]
		address = address[at+1:]
	}
	colon := strings.Index(address, ":")
	if strings.HasPrefix(address, "[") {
		closing := strings.Index(address, "]:")
		if closing < 0 {
			return sshDestination{}, false
		}
		colon = closing + 1
	}
	if colon <= 0 || colon == len(address)-1 || strings.Contains(address[:colon], "/") {
		return sshDestination{}, false
	}
	host := strings.Trim(address[:colon], "[]")
	return validSSHDestination(sshDestination{Host: host, User: user})
}

func validSSHDestination(destination sshDestination) (sshDestination, bool) {
	if destination.Host == "" || strings.HasPrefix(destination.Host, "-") || strings.ContainsAny(destination.Host, "\x00\r\n") {
		return sshDestination{}, false
	}
	if destination.User != "" && (strings.HasPrefix(destination.User, "-") || strings.ContainsAny(destination.User, "\x00\r\n")) {
		return sshDestination{}, false
	}
	if destination.Port != "" {
		port, err := strconv.Atoi(destination.Port)
		if err != nil || port < 1 || port > 65535 {
			return sshDestination{}, false
		}
	}
	return destination, true
}

func uniqueIdentityPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	return result
}

func runBootstrapIdentityCommand(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return string(output), nil
}
