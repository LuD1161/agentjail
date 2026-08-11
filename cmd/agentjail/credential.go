package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/LuD1161/agentjail/internal/credentialtools"
)

type credentialSourceOptions struct {
	Tool      string
	FromEnv   bool
	FromFile  string
	FromStdin bool
	Label     string
	Account   string
	Context   string
}

func buildCredentialValue(options credentialSourceOptions, stdin io.Reader, getenv func(string) string, readFile func(string) ([]byte, error)) (string, error) {
	tool, err := credentialtools.ParseTool(options.Tool)
	if err != nil {
		return "", err
	}
	sources := 0
	if options.FromEnv {
		sources++
	}
	if options.FromFile != "" {
		sources++
	}
	if options.FromStdin {
		sources++
	}
	if sources != 1 {
		return "", errors.New("select exactly one credential source: --from-current-env, --from-file, or --from-stdin")
	}

	var value string
	switch {
	case options.FromEnv:
		value, err = credentialValueFromEnv(tool, getenv, readFile)
	case options.FromFile != "":
		var data []byte
		data, err = readFile(options.FromFile)
		value = string(data)
	case options.FromStdin:
		const maxCredentialSize = 16 << 20
		var data []byte
		data, err = io.ReadAll(io.LimitReader(stdin, maxCredentialSize+1))
		if len(data) > maxCredentialSize {
			return "", errors.New("credential input exceeds 16 MiB")
		}
		value = string(data)
	}
	if err != nil {
		return "", err
	}
	material, err := credentialtools.DecodeStatic(tool, value)
	if err != nil {
		return "", err
	}
	adapter, _ := credentialtools.DefaultRegistry().Resolve(tool)
	if _, err := adapter.Present(material); err != nil {
		return "", err
	}
	record, err := credentialaccess.NewRecord(tool, value, options.Label, options.Account, options.Context)
	if err != nil {
		return "", err
	}
	return credentialaccess.Encode(record)
}

func credentialValueFromEnv(tool credentialtools.Tool, getenv func(string) string, readFile func(string) ([]byte, error)) (string, error) {
	switch tool {
	case credentialtools.ToolAWS:
		accessKey := getenv("AWS_ACCESS_KEY_ID")
		secretKey := getenv("AWS_SECRET_ACCESS_KEY")
		if accessKey == "" || secretKey == "" {
			return "", errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must both be set")
		}
		stored := struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token,omitempty"`
			Region          string `json:"region,omitempty"`
		}{
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
			SessionToken:    getenv("AWS_SESSION_TOKEN"),
			Region:          firstValue(getenv("AWS_REGION"), getenv("AWS_DEFAULT_REGION")),
		}
		data, err := json.Marshal(stored)
		return string(data), err
	case credentialtools.ToolGitHub:
		token := firstValue(getenv("GH_TOKEN"), getenv("GITHUB_TOKEN"))
		if token == "" {
			return "", errors.New("GH_TOKEN or GITHUB_TOKEN must be set")
		}
		return token, nil
	case credentialtools.ToolKubernetes:
		path := getenv("KUBECONFIG")
		if path == "" {
			return "", errors.New("KUBECONFIG must name exactly one file; use --from-file for an explicit kubeconfig")
		}
		if strings.ContainsRune(path, os.PathListSeparator) {
			return "", errors.New("KUBECONFIG contains multiple files; merge and select one context before importing")
		}
		data, err := readFile(path)
		return string(data), err
	default:
		return "", fmt.Errorf("environment import is not supported for %q", tool)
	}
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func callSecretsSetStdin(name, value string) error {
	bin, err := findSecretsBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "set", "--stdin", name)
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
