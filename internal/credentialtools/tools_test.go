package credentialtools

import (
	"fmt"
	"reflect"
	"testing"
)

func TestDefaultRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tool   Tool
		binary string
	}{
		{ToolAWS, "aws"},
		{ToolKubernetes, "kubectl"},
		{ToolGitHub, "gh"},
	}
	registry := DefaultRegistry()
	for _, tt := range tests {
		t.Run(string(tt.tool), func(t *testing.T) {
			adapter, err := registry.Resolve(tt.tool)
			if err != nil {
				t.Fatal(err)
			}
			if got := adapter.Binary(); got != tt.binary {
				t.Fatalf("Binary() = %q, want %q", got, tt.binary)
			}
		})
	}
}

func TestAWSStaticDelivery(t *testing.T) {
	t.Parallel()

	material, err := DecodeStatic(ToolAWS, `{
  "access_key_id": "AKIATEST",
  "secret_access_key": "secret",
  "session_token": "session",
  "region": "us-west-2"
}`)
	if err != nil {
		t.Fatal(err)
	}
	adapter, _ := DefaultRegistry().Resolve(ToolAWS)
	delivery, err := adapter.Present(material)
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", Value: "AKIATEST"},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: "secret"},
		{Name: "AWS_EC2_METADATA_DISABLED", Value: "true"},
		{Name: "AWS_SESSION_TOKEN", Value: "session"},
		{Name: "AWS_DEFAULT_REGION", Value: "us-west-2"},
	}
	if !reflect.DeepEqual(delivery.Env, want) {
		t.Fatalf("delivery env = %#v, want %#v", delivery.Env, want)
	}
	if len(delivery.Files) != 0 {
		t.Fatalf("delivery files = %#v, want none", delivery.Files)
	}
}

func TestAWSAcceptsLegacyFieldNames(t *testing.T) {
	t.Parallel()

	material, err := DecodeStatic(ToolAWS, `{"access_key":"AKIAOLD","secret_key":"old-secret"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := material.Fields[FieldAccessKeyID]; got != "AKIAOLD" {
		t.Fatalf("access key = %q, want AKIAOLD", got)
	}
	if got := material.Fields[FieldSecretAccessKey]; got != "old-secret" {
		t.Fatalf("secret key = %q, want old-secret", got)
	}
}

func TestAWSRejectsUnknownStoredFields(t *testing.T) {
	t.Parallel()

	if _, err := DecodeStatic(ToolAWS, `{"access_key_id":"a","secret_access_key":"b","typo":"silent"}`); err == nil {
		t.Fatal("DecodeStatic accepted an unknown AWS credential field")
	}
}

func TestKubectlDeliveryUsesOneSessionFile(t *testing.T) {
	t.Parallel()

	const kubeconfig = `apiVersion: v1
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
  context:
    cluster: test-cluster
    user: test-user
current-context: test
`
	material, err := DecodeStatic(ToolKubernetes, kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	adapter, _ := DefaultRegistry().Resolve(ToolKubernetes)
	delivery, err := adapter.Present(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Files) != 1 {
		t.Fatalf("delivery files = %d, want 1", len(delivery.Files))
	}
	file := delivery.Files[0]
	if file.EnvVar != "KUBECONFIG" || file.Name != "kubeconfig" || string(file.Content) != kubeconfig {
		t.Fatalf("unexpected kubeconfig delivery: %#v", file)
	}
}

func TestKubectlRejectsMultipleContexts(t *testing.T) {
	t.Parallel()

	const kubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: one
- name: two
users:
- name: user
contexts:
- name: one
  context: {cluster: one, user: user}
- name: two
  context: {cluster: two, user: user}
current-context: one
`
	if _, err := DecodeStatic(ToolKubernetes, kubeconfig); err == nil {
		t.Fatal("multi-context kubeconfig was accepted")
	}
}

func TestKubectlRejectsExternalCredentialSources(t *testing.T) {
	t.Parallel()

	const base = `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:6443
    %s
users:
- name: test-user
  user:
    %s
contexts:
- name: test
  context:
    cluster: test-cluster
    user: test-user
current-context: test
`
	tests := []struct {
		name    string
		cluster string
		user    string
	}{
		{name: "exec plugin", user: "exec: {command: steal, apiVersion: client.authentication.k8s.io/v1}"},
		{name: "auth provider", user: "auth-provider: {name: oidc, config: {client-id: secret}}"},
		{name: "token file", user: "tokenFile: /home/user/.token"},
		{name: "client key file", user: "client-certificate: /home/user/cert\n    client-key: /home/user/key"},
		{name: "certificate authority file", cluster: "certificate-authority: /home/user/ca"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeStatic(ToolKubernetes, fmt.Sprintf(base, tt.cluster, tt.user)); err == nil {
				t.Fatalf("kubeconfig with %s was accepted", tt.name)
			}
		})
	}
}

func TestKubectlRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	t.Parallel()

	const valid = `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster: {server: https://127.0.0.1:6443}
users:
- name: test-user
  user: {token: test-token}
contexts:
- name: test
  context: {cluster: test-cluster, user: test-user}
current-context: test
`
	if _, err := DecodeStatic(ToolKubernetes, valid+"unexpected-field: true\n"); err == nil {
		t.Fatal("kubeconfig with unknown field was accepted")
	}
	if _, err := DecodeStatic(ToolKubernetes, valid+"---\nkind: Config\n"); err == nil {
		t.Fatal("multi-document kubeconfig was accepted")
	}
}

func TestGitHubDeliveryUsesEnvironment(t *testing.T) {
	t.Parallel()

	material, err := DecodeStatic(ToolGitHub, "ghp_test\n")
	if err != nil {
		t.Fatal(err)
	}
	adapter, _ := DefaultRegistry().Resolve(ToolGitHub)
	delivery, err := adapter.Present(material)
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvVar{{Name: "GH_TOKEN", Value: "ghp_test"}, {Name: "GH_PROMPT_DISABLED", Value: "1"}}
	if !reflect.DeepEqual(delivery.Env, want) {
		t.Fatalf("delivery env = %#v, want %#v", delivery.Env, want)
	}
	wantDirectories := []SessionDirectory{{EnvVar: "GH_CONFIG_DIR", Name: "gh-config"}}
	if !reflect.DeepEqual(delivery.Directories, wantDirectories) {
		t.Fatalf("delivery directories = %#v, want %#v", delivery.Directories, wantDirectories)
	}
}

func TestAdaptersRejectMissingMaterial(t *testing.T) {
	t.Parallel()

	for _, tool := range []Tool{ToolAWS, ToolKubernetes, ToolGitHub} {
		adapter, _ := DefaultRegistry().Resolve(tool)
		if _, err := adapter.Present(Material{Fields: map[Field]string{}}); err == nil {
			t.Errorf("%s adapter accepted empty material", tool)
		}
	}
}
