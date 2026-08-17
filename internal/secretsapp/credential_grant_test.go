package secretsapp

import (
	"context"
	"errors"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/LuD1161/agentjail/internal/credentials"
)

func newCredentialGrantFixture(t *testing.T) (*Store, *credentials.GrantManager, *credentialaccess.Service) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir+"/secrets", dir+"/secrets.key")
	if err != nil {
		t.Fatal(err)
	}
	return store, credentials.NewGrantManager(), credentialaccess.NewService(
		store, credentialaccess.AllowAllBrokerCredentials{}, audit.NopEmitter{}, true,
	)
}

func credentialGrantRequest(name string) *RPCRequest {
	return &RPCRequest{Action: "credential_grant", Name: name, SessionID: "shield-test", Project: "/project", Agent: "test"}
}

func storeCredentialRecord(t *testing.T, store *Store, name string, delivery credentialaccess.Delivery) {
	t.Helper()
	record, err := credentialaccess.NewRecord(delivery, "Test credential", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := credentialaccess.Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(name, raw); err != nil {
		t.Fatal(err)
	}
}

func TestHandleCredentialGrantGenericEnvironment(t *testing.T) {
	t.Parallel()
	store, gm, access := newCredentialGrantFixture(t)
	storeCredentialRecord(t, store, "anything", credentialaccess.Delivery{Env: []credentialaccess.EnvVar{
		{Name: "CUSTOM_ACCESS_ID", Value: "identifier"}, {Name: "CUSTOM_SECRET", Value: "secret"},
	}})
	resp := handleRPC(credentialGrantRequest("anything"), store, gm, audit.NopEmitter{}, access)
	if !resp.OK || resp.Delivery == nil {
		t.Fatalf("credential grant: %+v", resp)
	}
	env := deliveryEnv(resp.Delivery.Env)
	if env["CUSTOM_ACCESS_ID"] != "identifier" || env["CUSTOM_SECRET"] != "secret" {
		t.Fatalf("delivery = %#v", env)
	}
	if gm.Active() != 1 {
		t.Fatalf("active grants = %d, want 1", gm.Active())
	}
}

func TestHandleCredentialGrantGenericFile(t *testing.T) {
	t.Parallel()
	store, gm, access := newCredentialGrantFixture(t)
	storeCredentialRecord(t, store, "cluster-config", credentialaccess.Delivery{Files: []credentialaccess.SessionFile{{
		EnvVar: "CLUSTER_CONFIG", Name: "credential-1", Content: []byte("config-content"),
	}}})
	resp := handleRPC(credentialGrantRequest("cluster-config"), store, gm, audit.NopEmitter{}, access)
	if !resp.OK || resp.Delivery == nil || len(resp.Delivery.Files) != 1 {
		t.Fatalf("delivery = %#v", resp)
	}
	if file := resp.Delivery.Files[0]; file.EnvVar != "CLUSTER_CONFIG" || string(file.Content) != "config-content" {
		t.Fatalf("file = %#v", file)
	}
}

func TestHandleCredentialGrantRejectsRawAndMissingValues(t *testing.T) {
	t.Parallel()
	store, gm, access := newCredentialGrantFixture(t)
	if err := store.Set("raw", "plain-secret"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"raw", "missing"} {
		if resp := handleRPC(credentialGrantRequest(name), store, gm, audit.NopEmitter{}, access); resp.OK {
			t.Fatalf("credential grant %q succeeded", name)
		}
	}
}

type failingCredentialAudit struct{}

func (failingCredentialAudit) Emit(_ context.Context, event audit.Event) error {
	if event.EventType == audit.CredentialAccessIssued {
		return errors.New("audit unavailable")
	}
	return nil
}

func TestHandleCredentialGrantFailsClosedWithoutDurableIssuanceAudit(t *testing.T) {
	t.Parallel()
	store, gm, _ := newCredentialGrantFixture(t)
	storeCredentialRecord(t, store, "anything", credentialaccess.Delivery{
		Env: []credentialaccess.EnvVar{{Name: "CUSTOM_SECRET", Value: "secret"}},
	})
	emitter := failingCredentialAudit{}
	access := credentialaccess.NewService(store, credentialaccess.AllowAllBrokerCredentials{}, emitter, true)
	resp := handleRPC(credentialGrantRequest("anything"), store, gm, emitter, access)
	if resp.OK || resp.Delivery != nil {
		t.Fatalf("credential grant crossed failed audit boundary: %+v", resp)
	}
	if gm.Active() != 0 {
		t.Fatalf("active grants = %d, want 0", gm.Active())
	}
}

func TestCredentialControlActionsDoNotOverwriteOrDeleteRawBrokerEntries(t *testing.T) {
	t.Parallel()
	store, gm, access := newCredentialGrantFixture(t)
	if err := store.Set("shared-name", "raw-secret"); err != nil {
		t.Fatal(err)
	}
	record, err := credentialaccess.NewRecord(credentialaccess.Delivery{
		Env: []credentialaccess.EnvVar{{Name: "TOKEN", Value: "credential-secret"}},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := credentialaccess.Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	if resp := handleRPC(&RPCRequest{Action: "credential_set", Name: "shared-name", Value: encoded}, store, gm, audit.NopEmitter{}, access); resp.OK {
		t.Fatal("credential set overwrote a raw broker entry")
	}
	if resp := handleRPC(&RPCRequest{Action: "credential_delete", Name: "shared-name"}, store, gm, audit.NopEmitter{}, access); resp.OK {
		t.Fatal("credential delete removed a raw broker entry")
	}
	if got, err := store.Get("shared-name"); err != nil || got != "raw-secret" {
		t.Fatalf("raw broker entry changed: value=%q err=%v", got, err)
	}
	if resp := handleRPC(&RPCRequest{Action: "credential_set", Name: "credential", Value: encoded}, store, gm, audit.NopEmitter{}, access); !resp.OK {
		t.Fatalf("credential set failed: %s", resp.Error)
	}
	if resp := handleRPC(&RPCRequest{Action: "credential_delete", Name: "credential"}, store, gm, audit.NopEmitter{}, access); !resp.OK {
		t.Fatalf("credential delete failed: %s", resp.Error)
	}
}

func deliveryEnv(vars []credentialaccess.EnvVar) map[string]string {
	result := make(map[string]string, len(vars))
	for _, variable := range vars {
		result[variable.Name] = variable.Value
	}
	return result
}
