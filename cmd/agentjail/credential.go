package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
)

const maxCredentialSize = 16 << 20

type credentialSourceOptions struct {
	FromEnv      []string
	FromFile     []string
	FromStdinEnv string
	Label        string
	Tags         []string
}

func buildCredentialValue(options credentialSourceOptions, stdin io.Reader, getenv func(string) string, readFile func(string) ([]byte, error)) (string, error) {
	if options.FromStdinEnv != "" && (len(options.FromEnv) != 0 || len(options.FromFile) != 0) {
		return "", errors.New("--from-stdin cannot be combined with --from-env or --from-file")
	}
	if options.FromStdinEnv == "" && len(options.FromEnv) == 0 && len(options.FromFile) == 0 {
		return "", errors.New("select at least one credential source: --from-env, --from-file, or --from-stdin")
	}

	delivery := credentialaccess.Delivery{}
	for _, name := range options.FromEnv {
		name = strings.TrimSpace(name)
		value := getenv(name)
		if value == "" {
			return "", fmt.Errorf("environment variable %s is unset or empty", name)
		}
		delivery.Env = append(delivery.Env, credentialaccess.EnvVar{Name: name, Value: value})
	}
	for index, binding := range options.FromFile {
		envName, path, ok := strings.Cut(binding, "=")
		envName = strings.TrimSpace(envName)
		path = strings.TrimSpace(path)
		if !ok || envName == "" || path == "" {
			return "", fmt.Errorf("--from-file must be ENV=PATH, got %q", binding)
		}
		data, err := readBoundedCredentialFile(path, readFile)
		if err != nil {
			return "", err
		}
		delivery.Files = append(delivery.Files, credentialaccess.SessionFile{
			EnvVar: envName, Name: fmt.Sprintf("credential-%d", index+1), Content: data,
		})
	}
	if options.FromStdinEnv != "" {
		data, err := readCredentialInput(stdin)
		if err != nil {
			return "", err
		}
		delivery.Env = append(delivery.Env, credentialaccess.EnvVar{Name: strings.TrimSpace(options.FromStdinEnv), Value: string(data)})
	}
	record, err := credentialaccess.NewRecord(delivery, options.Label, options.Tags)
	if err != nil {
		return "", err
	}
	return credentialaccess.Encode(record)
}

func readBoundedCredentialFile(path string, readFile func(string) ([]byte, error)) ([]byte, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential file %s: %w", path, err)
	}
	if len(data) > maxCredentialSize {
		return nil, fmt.Errorf("credential file %s exceeds 16 MiB", path)
	}
	return data, nil
}

func readCredentialInput(stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, maxCredentialSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCredentialSize {
		return nil, errors.New("credential input exceeds 16 MiB")
	}
	return data, nil
}

func callSecretsSetStdin(name, value string) error {
	bin, err := findSecretsBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "credential-set", "--stdin", name)
	cmd.Stdin = strings.NewReader(value)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func callSecretsCommand(args ...string) error {
	bin, err := findSecretsBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
