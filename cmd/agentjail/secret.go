package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func runSecret(args []string) int {
	bin, err := findSecretsBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail secret: %v\n", err)
		return 1
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "agentjail secret: %v\n", err)
		return 1
	}
	return 0
}

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
