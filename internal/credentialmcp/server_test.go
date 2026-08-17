package credentialmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
)

type fakeBroker struct {
	requestedID credentialaccess.ID
	reason      string
}

func (b *fakeBroker) List(context.Context) ([]credentialaccess.Descriptor, error) {
	return []credentialaccess.Descriptor{
		{ID: "aws-read-only-cred-prod", Label: "Production read only", Tags: []string{"aws", "prod"}, Approval: "automatic"},
		{ID: "slack-channel-read-token", Label: "Support channel", Tags: []string{"slack"}, Approval: "automatic"},
	}, nil
}
func (b *fakeBroker) Request(_ context.Context, id credentialaccess.ID, reason string) (credentialaccess.Issuance, error) {
	b.requestedID, b.reason = id, reason
	return credentialaccess.Issuance{
		Credential: credentialaccess.Descriptor{ID: id, Tags: []string{"slack"}, Approval: "automatic"},
		Delivery:   credentialaccess.Delivery{Env: []credentialaccess.EnvVar{{Name: "SLACK_TOKEN", Value: "secret-token"}}},
	}, nil
}

func TestServerListsMetadataThenRequestsExactCredential(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"codex","version":"0.147.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_credentials","arguments":{},"_meta":{"progressToken":"codex-call-3"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_credential","arguments":{"credential_id":"slack-channel-read-token"}}}`,
	}, "\n") + "\n"
	broker := &fakeBroker{}
	var output bytes.Buffer
	if err := Run(context.Background(), strings.NewReader(input), &output, broker); err != nil {
		t.Fatal(err)
	}
	if broker.requestedID != "slack-channel-read-token" || broker.reason != "" {
		t.Fatalf("request = %q (%q)", broker.requestedID, broker.reason)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("responses = %d, want 4\n%s", len(lines), output.String())
	}
	if strings.Contains(lines[2], "secret-token") {
		t.Fatal("list_credentials leaked credential material")
	}
	if !strings.Contains(lines[2], "aws-read-only-cred-prod") || !strings.Contains(lines[3], "SLACK_TOKEN") {
		t.Fatalf("unexpected responses:\n%s", output.String())
	}
	for _, line := range lines {
		var response map[string]interface{}
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatal(err)
		}
	}
}

func TestServerAcceptsProtocolMetadataButKeepsArgumentsStrict(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_credentials","arguments":{},"_meta":{"progressToken":7}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_credentials","arguments":{"tool":"aws"},"_meta":{"progressToken":8}}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := Run(context.Background(), strings.NewReader(input), &output, &fakeBroker{}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || strings.Contains(lines[0], `"code":-32602`) || !strings.Contains(lines[1], `"code":-32602`) {
		t.Fatalf("responses = %s", output.String())
	}
}

func TestServerRejectsUnknownRequestFields(t *testing.T) {
	t.Parallel()
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_credential","arguments":{"credential_id":"credential","account":"guess"}}}` + "\n"
	var output bytes.Buffer
	if err := Run(context.Background(), strings.NewReader(input), &output, &fakeBroker{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"code":-32602`) {
		t.Fatalf("response = %s", output.String())
	}
}
