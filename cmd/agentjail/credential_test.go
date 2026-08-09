package main

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildCredentialValueAWSFromEnvironment(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIATEST",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "session",
		"AWS_REGION":            "us-west-1",
	}
	value, err := buildCredentialValue(credentialSourceOptions{Tool: "aws", FromEnv: true}, strings.NewReader(""), func(key string) string { return env[key] }, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AKIATEST", "secret", "session", "us-west-1"} {
		if !strings.Contains(value, want) {
			t.Fatalf("stored AWS JSON does not contain expected field %q", want)
		}
	}
}

func TestBuildCredentialValueKubectlFromFile(t *testing.T) {
	t.Parallel()
	const config = `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:6443
users:
- name: test-user
  user:
    token: test-token
contexts:
- name: test
  context: {cluster: test-cluster, user: test-user}
current-context: test
`
	value, err := buildCredentialValue(credentialSourceOptions{Tool: "kubectl", FromFile: "/tmp/config"}, strings.NewReader(""), nil, func(path string) ([]byte, error) {
		if path != "/tmp/config" {
			t.Fatalf("read path = %q", path)
		}
		return []byte(config), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != config {
		t.Fatalf("value = %q, want kubeconfig", value)
	}
}

func TestBuildCredentialValueGitHubFromStdin(t *testing.T) {
	t.Parallel()
	value, err := buildCredentialValue(credentialSourceOptions{Tool: "gh", FromStdin: true}, strings.NewReader("ghp_test"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value != "ghp_test" {
		t.Fatalf("value = %q", value)
	}
}

func TestBuildCredentialValueRequiresOneSource(t *testing.T) {
	t.Parallel()
	for _, options := range []credentialSourceOptions{
		{Tool: "gh"},
		{Tool: "gh", FromEnv: true, FromStdin: true},
	} {
		if _, err := buildCredentialValue(options, strings.NewReader("x"), func(string) string { return "x" }, func(string) ([]byte, error) { return []byte("x"), nil }); err == nil {
			t.Fatalf("source selection succeeded: %#v", options)
		}
	}
}

func TestCredentialValueFromEnvRejectsKubeconfigList(t *testing.T) {
	t.Parallel()
	_, err := credentialValueFromEnv("kubectl", func(string) string { return "/a:/b" }, func(string) ([]byte, error) {
		return nil, errors.New("must not read")
	})
	if err == nil {
		t.Fatal("multiple kubeconfigs were accepted")
	}
}
