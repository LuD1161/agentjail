package secretsapp

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/LuD1161/agentjail/internal/credentials"
	"github.com/LuD1161/agentjail/internal/credentialtools"
)

func newToolGrantFixture(t *testing.T) (*Store, *credentials.GrantManager) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir+"/secrets", dir+"/secrets.key")
	if err != nil {
		t.Fatal(err)
	}
	return store, credentials.NewGrantManager()
}

func TestHandleToolGrantAWSStatic(t *testing.T) {
	t.Parallel()
	store, gm := newToolGrantFixture(t)
	if err := store.Set("aws/default", `{"access_key_id":"AKIATEST","secret_access_key":"secret","region":"us-east-2"}`); err != nil {
		t.Fatal(err)
	}

	resp := handleRPC(&RPCRequest{
		Action: "tool_grant",
		Tool:   "aws",
		Name:   "aws/default",
	}, store, gm, audit.NopEmitter{})
	if !resp.OK {
		t.Fatalf("tool grant failed: %s", resp.Error)
	}
	if resp.Delivery == nil {
		t.Fatal("tool grant returned no delivery")
	}
	env := deliveryEnv(resp.Delivery.Env)
	if env["AWS_ACCESS_KEY_ID"] != "AKIATEST" || env["AWS_SECRET_ACCESS_KEY"] != "secret" {
		t.Fatalf("unexpected AWS delivery: %#v", env)
	}
	if env["AWS_EC2_METADATA_DISABLED"] != "true" {
		t.Fatalf("metadata fallback not disabled: %#v", env)
	}
	if gm.Active() != 1 {
		t.Fatalf("active grants = %d, want 1", gm.Active())
	}
}

func TestHandleToolGrantKubectlFile(t *testing.T) {
	t.Parallel()
	store, gm := newToolGrantFixture(t)
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
  context: {cluster: test-cluster, user: test-user}
current-context: test
`
	if err := store.Set("kube/default", kubeconfig); err != nil {
		t.Fatal(err)
	}

	resp := handleRPC(&RPCRequest{
		Action: "tool_grant",
		Tool:   "kubectl",
		Name:   "kube/default",
	}, store, gm, audit.NopEmitter{})
	if !resp.OK {
		t.Fatalf("tool grant failed: %s", resp.Error)
	}
	if resp.Delivery == nil || len(resp.Delivery.Files) != 1 {
		t.Fatalf("unexpected delivery: %#v", resp.Delivery)
	}
	file := resp.Delivery.Files[0]
	if file.EnvVar != "KUBECONFIG" || string(file.Content) != kubeconfig {
		t.Fatalf("unexpected kubeconfig file: %#v", file)
	}
}

func TestHandleToolGrantGitHubEnvironment(t *testing.T) {
	t.Parallel()
	store, gm := newToolGrantFixture(t)
	if err := store.Set("github/default", "ghp_test"); err != nil {
		t.Fatal(err)
	}

	resp := handleRPC(&RPCRequest{
		Action: "tool_grant",
		Tool:   "gh",
		Name:   "github/default",
	}, store, gm, audit.NopEmitter{})
	if !resp.OK {
		t.Fatalf("tool grant failed: %s", resp.Error)
	}
	if got := deliveryEnv(resp.Delivery.Env)["GH_TOKEN"]; got != "ghp_test" {
		t.Fatalf("GH_TOKEN = %q, want test token", got)
	}
}

func TestHandleToolGrantTypedRecordRejectsToolMismatch(t *testing.T) {
	t.Parallel()
	store, gm := newToolGrantFixture(t)
	record, err := credentialaccess.NewRecord(credentialtools.ToolAWS, `{"access_key_id":"AKIATEST","secret_access_key":"secret"}`, "Development", "111122223333", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := credentialaccess.Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("aws/development", raw); err != nil {
		t.Fatal(err)
	}
	resp := handleRPC(&RPCRequest{Action: "tool_grant", Tool: "gh", Name: "aws/development"}, store, gm, audit.NopEmitter{})
	if resp.OK {
		t.Fatal("typed AWS credential was issued as a GitHub credential")
	}
}

func TestHandleToolGrantRejectsUnknownToolAndMissingCredential(t *testing.T) {
	t.Parallel()
	store, gm := newToolGrantFixture(t)

	unknown := handleRPC(&RPCRequest{Action: "tool_grant", Tool: "terraform", Name: "x"}, store, gm, audit.NopEmitter{})
	if unknown.OK {
		t.Fatal("unknown tool grant succeeded")
	}
	missing := handleRPC(&RPCRequest{Action: "tool_grant", Tool: "gh", Name: "missing"}, store, gm, audit.NopEmitter{})
	if missing.OK {
		t.Fatal("missing credential grant succeeded")
	}
}

func deliveryEnv(vars []credentialtools.EnvVar) map[string]string {
	result := make(map[string]string, len(vars))
	for _, variable := range vars {
		result[variable.Name] = variable.Value
	}
	return result
}
