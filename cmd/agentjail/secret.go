package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// callSecretsDelete invokes the typed credential delete path.
func callSecretsDelete(name string) error {
	bin, err := findSecretsBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "credential-delete", name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// findSecretsBinary locates the agentjail-secrets binary, first checking
// next to the current executable, then falling back to PATH.
func findSecretsBinary() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "agentjail-secrets")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath("agentjail-secrets"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("agentjail-secrets not found in install dir or PATH")
}
