package secretsapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentialaccess"
	eventstore "github.com/LuD1161/agentjail/internal/store"
)

func TestCredentialLifecycleLeavesNoPlaintextInEventStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agentjail.db")
	emitter, err := eventstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open event store: %v", err)
	}

	vault, err := NewStore(filepath.Join(dir, "secrets"), filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatalf("open credential vault: %v", err)
	}
	const (
		accessKey = "AKIAZ9Y8X7W6V5U4T3S2"
		secretKey = "agentjail-repro-secret-20260815"
		token     = "agentjail-repro-token-20260815"
	)
	record, err := credentialaccess.NewRecord(credentialaccess.Delivery{Env: []credentialaccess.EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", Value: accessKey},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: secretKey},
		{Name: "AWS_SESSION_TOKEN", Value: token},
	}}, "Storage hygiene", []string{"aws", "test"})
	if err != nil {
		t.Fatalf("build credential record: %v", err)
	}
	encoded, err := credentialaccess.Encode(record)
	if err != nil {
		t.Fatalf("encode credential record: %v", err)
	}
	if err := vault.Set("aws/repro", encoded); err != nil {
		t.Fatalf("store credential: %v", err)
	}
	ctx := context.Background()
	if err := emitter.Emit(ctx, audit.Event{EventType: audit.CredentialStored, Entity: "aws/repro", Actor: "test"}); err != nil {
		t.Fatalf("audit credential storage: %v", err)
	}

	service := credentialaccess.NewService(vault, credentialaccess.AllowAllBrokerCredentials{}, emitter, true)
	session := credentialaccess.Session{ID: "storage-hygiene", Project: dir, Agent: "codex"}
	if _, err := service.RequestExact(ctx, session, credentialaccess.Request{CredentialID: "aws/repro", Reason: "verify exact storage hygiene"}); err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	if err := vault.Delete("aws/repro"); err != nil {
		t.Fatalf("delete credential: %v", err)
	}
	if err := emitter.Emit(ctx, audit.Event{EventType: audit.CredentialRemoved, Entity: "aws/repro", Actor: "test"}); err != nil {
		t.Fatalf("audit credential removal: %v", err)
	}
	if err := emitter.Close(); err != nil {
		t.Fatalf("close event store: %v", err)
	}

	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", filepath.Base(path), err)
		}
		for _, marker := range []string{accessKey, secretKey, token} {
			if bytes.Contains(data, []byte(marker)) {
				t.Errorf("%s retains plaintext credential marker", filepath.Base(path))
			}
		}
	}
}
