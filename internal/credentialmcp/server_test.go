package credentialmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/LuD1161/agentjail/internal/credentialtools"
)

type fakeBroker struct {
	listedTool  string
	requestedID credentialaccess.ID
	reason      string
}

func (b *fakeBroker) List(context.Context, string) ([]credentialaccess.Descriptor, error) {
	return []credentialaccess.Descriptor{
		{ID: "aws/development", Tool: "aws", Kind: "access_key", Label: "Development", Account: "111111111111", Approval: "automatic"},
		{ID: "aws/production", Tool: "aws", Kind: "access_key", Label: "Production", Account: "222222222222", Approval: "automatic"},
	}, nil
}

func (b *fakeBroker) Request(_ context.Context, id credentialaccess.ID, reason string) (credentialaccess.Issuance, error) {
	b.requestedID, b.reason = id, reason
	return credentialaccess.Issuance{
		Credential: credentialaccess.Descriptor{ID: id, Tool: "aws", Kind: "access_key", Account: "222222222222", Approval: "automatic"},
		Delivery: credentialtools.Delivery{Env: []credentialtools.EnvVar{
			{Name: "AWS_ACCESS_KEY_ID", Value: "AKIAPRODUCTION"},
			{Name: "AWS_SECRET_ACCESS_KEY", Value: "production-secret"},
		}},
	}, nil
}

func TestServerListsMetadataThenRequestsExactCredential(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"codex","version":"0.147.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_credentials","arguments":{"tool":"aws"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_credential","arguments":{"credential_id":"aws/production","reason":"Read the requested production S3 report"}}}`,
	}, "\n") + "\n"
	broker := &fakeBroker{}
	var output bytes.Buffer
	if err := Run(context.Background(), strings.NewReader(input), &output, broker); err != nil {
		t.Fatal(err)
	}
	if broker.requestedID != "aws/production" || broker.reason != "Read the requested production S3 report" {
		t.Fatalf("request = %q (%q)", broker.requestedID, broker.reason)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("responses = %d, want 4\n%s", len(lines), output.String())
	}
	if strings.Contains(lines[2], "production-secret") || strings.Contains(lines[2], "AKIAPRODUCTION") {
		t.Fatal("list_credentials leaked credential material")
	}
	if !strings.Contains(lines[2], "aws/production") || !strings.Contains(lines[3], "AWS_ACCESS_KEY_ID") {
		t.Fatalf("unexpected tool responses:\n%s", output.String())
	}
	for _, line := range lines {
		var response map[string]interface{}
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("invalid JSON-RPC response: %v", err)
		}
	}
}

func TestServerRejectsUnknownRequestFields(t *testing.T) {
	t.Parallel()
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_credential","arguments":{"credential_id":"aws/production","reason":"read S3","account":"guess"}}}` + "\n"
	var output bytes.Buffer
	if err := Run(context.Background(), strings.NewReader(input), &output, &fakeBroker{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"code":-32602`) {
		t.Fatalf("response = %s", output.String())
	}
}
