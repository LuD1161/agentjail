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
	for _, directory := range directories {
		candidate := filepath.Join(directory, command)
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("executable not found")
}
