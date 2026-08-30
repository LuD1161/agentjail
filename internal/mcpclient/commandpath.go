package mcpclient

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func resolveConfiguredCommand(command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("empty command")
	}
	if strings.ContainsRune(command, filepath.Separator) {
		return exec.LookPath(command)
	}
	if path, err := exec.LookPath(command); err == nil {
		return path, nil
	}

	home, _ := os.UserHomeDir()
	directories := commandSearchDirectories(home)
	for _, directory := range directories {
		candidate := filepath.Join(directory, command)
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("executable not found")
}

// configuredCommandEnv makes direct executable resolution effective for
// env-based shebang interpreters too. See ADR 0146-mcp-command-resolution.
func configuredCommandEnv(command string) []string {
	env := sanitizedEnv()
	home, _ := os.UserHomeDir()
	directories := []string{filepath.Dir(command)}
	directories = append(directories, commandSearchDirectories(home)...)
	if inherited := envValue(env, "PATH"); inherited != "" {
		for _, directory := range filepath.SplitList(inherited) {
			if filepath.IsAbs(directory) {
				directories = append(directories, directory)
			}
		}
	}
	directories = uniqueDirectories(directories)
	return replaceEnvValue(env, "PATH", strings.Join(directories, string(os.PathListSeparator)))
}

func commandSearchDirectories(home string) []string {
	directories := append([]string{}, platformCommandSearchDirectories()...)
	if home != "" {
		for _, relative := range []string{
			".local/bin",
			".bun/bin",
			".volta/bin",
			".local/share/mise/shims",
			".asdf/shims",
		} {
			directories = append(directories, filepath.Join(home, relative))
		}
	}
	return append(directories, "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
}

func uniqueDirectories(directories []string) []string {
	seen := make(map[string]struct{}, len(directories))
	result := make([]string, 0, len(directories))
	for _, directory := range directories {
		directory = filepath.Clean(strings.TrimSpace(directory))
		if !filepath.IsAbs(directory) {
			continue
		}
		if _, exists := seen[directory]; exists {
			continue
		}
		seen[directory] = struct{}{}
		result = append(result, directory)
	}
	return result
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix)
		}
	}
	return ""
}

func replaceEnvValue(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}
