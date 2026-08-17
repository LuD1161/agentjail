package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/spf13/cobra"
)

func TestCredentialSetReportsRejectedBinding(t *testing.T) {
	previousFromEnv := credentialSetFromEnv
	previousFromFile := credentialSetFromFile
	previousFromStdin := credentialSetFromStdinEnv
	previousLabel := credentialSetLabel
	previousTags := credentialSetTags
	t.Cleanup(func() {
		credentialSetFromEnv = previousFromEnv
		credentialSetFromFile = previousFromFile
		credentialSetFromStdinEnv = previousFromStdin
		credentialSetLabel = previousLabel
		credentialSetTags = previousTags
	})

	credentialSetFromEnv = []string{"PATH"}
	credentialSetFromFile = nil
	credentialSetFromStdinEnv = ""
	credentialSetLabel = ""
	credentialSetTags = nil
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	err := credentialSetCmd.RunE(cmd, []string{"unsafe-session-binding"})
	if err == nil {
		t.Fatal("unsafe PATH binding succeeded")
	}
	if !strings.Contains(stderr.String(), "can alter session security") {
		t.Fatalf("stderr = %q, want security rejection", stderr.String())
	}
}

func TestBuildCredentialValueFromEnvironment(t *testing.T) {
	t.Parallel()
	env := map[string]string{"AWS_ACCESS_KEY_ID": "AKIATEST", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "session"}
	value, err := buildCredentialValue(credentialSourceOptions{
		FromEnv: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
		Label:   "Production read only", Tags: []string{"prod", "aws"},
	}, strings.NewReader(""), func(key string) string { return env[key] }, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, recognized, err := credentialaccess.Decode(value)
	if err != nil || !recognized {
		t.Fatalf("Decode() = %#v, %v, %v", record, recognized, err)
	}
	if len(record.Delivery.Env) != 3 {
		t.Fatalf("delivery = %#v", record.Delivery)
	}
	if descriptor := credentialaccess.Describe("anything", record); descriptor.Label != "Production read only" || strings.Join(descriptor.Tags, ",") != "aws,prod" {
		t.Fatalf("descriptor = %#v", descriptor)
	}
}

func TestBuildCredentialValueFromFile(t *testing.T) {
	t.Parallel()
	value, err := buildCredentialValue(credentialSourceOptions{FromFile: []string{"KUBECONFIG=/tmp/config"}}, strings.NewReader(""), nil, func(path string) ([]byte, error) {
		if path != "/tmp/config" {
			t.Fatalf("read path = %q", path)
		}
		return []byte("credential-file"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record, recognized, err := credentialaccess.Decode(value)
	if err != nil || !recognized || string(record.Delivery.Files[0].Content) != "credential-file" || record.Delivery.Files[0].EnvVar != "KUBECONFIG" {
		t.Fatalf("decoded value = %#v, %v, %v", record, recognized, err)
	}
}

func TestBuildCredentialValueFromStdin(t *testing.T) {
	t.Parallel()
	value, err := buildCredentialValue(credentialSourceOptions{FromStdinEnv: "SLACK_TOKEN"}, strings.NewReader("token"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(value, "token") {
		t.Fatalf("value = %q", value)
	}
}

func TestBuildCredentialValueValidatesSourcesAndBindings(t *testing.T) {
	t.Parallel()
	tests := []credentialSourceOptions{
		{},
		{FromEnv: []string{"TOKEN"}, FromStdinEnv: "OTHER_TOKEN"},
		{FromFile: []string{"missing-equals"}},
		{FromStdinEnv: "PATH"},
	}
	for _, options := range tests {
		if _, err := buildCredentialValue(options, strings.NewReader("x"), func(string) string { return "x" }, func(string) ([]byte, error) { return []byte("x"), nil }); err == nil {
			t.Fatalf("invalid source succeeded: %#v", options)
		}
	}
	if _, err := buildCredentialValue(credentialSourceOptions{FromEnv: []string{"MISSING"}}, strings.NewReader(""), func(string) string { return "" }, nil); err == nil {
		t.Fatal("empty environment source succeeded")
	}
	if _, err := readBoundedCredentialFile("x", func(string) ([]byte, error) { return nil, errors.New("read failed") }); err == nil {
		t.Fatal("file read error was lost")
	}
}
