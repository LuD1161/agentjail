package credentialaccess

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentialtools"
)

type memoryVault map[string]string

func (v memoryVault) List() ([]string, error) {
	names := make([]string, 0, len(v))
	for name := range v {
		names = append(names, name)
	}
	return names, nil
}
func (v memoryVault) Get(name string) (string, error) {
	value, ok := v[name]
	if !ok {
		return "", errors.New("not found")
	}
	return value, nil
}

type eventEmitter struct {
	events []audit.Event
	failAt string
}

func (e *eventEmitter) Emit(_ context.Context, event audit.Event) error {
	if event.EventType == e.failAt {
		return errors.New("injected audit failure")
	}
	e.events = append(e.events, event)
	return nil
}

func encodedAWS(t *testing.T, label, account, key string) string {
	t.Helper()
	record, err := NewRecord(credentialtools.ToolAWS, `{"access_key_id":"`+key+`","secret_access_key":"secret-`+key+`"}`, label, account, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestListAndRequestExactAcrossMultipleAccounts(t *testing.T) {
	t.Parallel()
	vault := memoryVault{
		"aws/development": encodedAWS(t, "Development", "111122223333", "AKIADEV"),
		"aws/production":  encodedAWS(t, "Production", "444455556666", "AKIAPROD"),
		"untyped-secret":  "must-not-be-visible",
	}
	emitter := &eventEmitter{}
	service := NewService(vault, AllowAllBrokerCredentials{}, emitter, true)
	session := Session{ID: "session-1", Project: "/repo", Agent: "codex"}

	items, err := service.List(context.Background(), session, credentialtools.ToolAWS)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "aws/development" || items[1].ID != "aws/production" {
		t.Fatalf("items = %#v", items)
	}
	issuance, err := service.RequestExact(context.Background(), session, Request{
		CredentialID: "aws/production",
		Reason:       "Read the requested production S3 report",
	})
	if err != nil {
		t.Fatal(err)
	}
	env := make(map[string]string)
	for _, variable := range issuance.Delivery.Env {
		env[variable.Name] = variable.Value
	}
	if env["AWS_ACCESS_KEY_ID"] != "AKIAPROD" || strings.Contains(env["AWS_SECRET_ACCESS_KEY"], "AKIADEV") {
		t.Fatalf("wrong credential issued: %#v", env)
	}
	for _, event := range emitter.events {
		for _, value := range event.Detail {
			if strings.Contains(value, "secret-AKIAPROD") {
				t.Fatal("audit detail contains credential material")
			}
		}
	}
}

func TestRequestRequiresDurableReasonedAudit(t *testing.T) {
	t.Parallel()
	vault := memoryVault{"aws/development": encodedAWS(t, "Development", "111122223333", "AKIADEV")}
	session := Session{ID: "session-1", Project: "/repo", Agent: "codex"}
	for _, test := range []struct {
		name    string
		reason  string
		durable bool
		failAt  string
	}{
		{name: "empty reason", durable: true},
		{name: "oversized reason", reason: strings.Repeat("x", MaxReasonBytes+1), durable: true},
		{name: "audit unavailable", reason: "read report"},
		{name: "request audit fails", reason: "read report", durable: true, failAt: audit.CredentialAccessRequested},
		{name: "issued audit fails", reason: "read report", durable: true, failAt: audit.CredentialAccessIssued},
	} {
		t.Run(test.name, func(t *testing.T) {
			emitter := &eventEmitter{failAt: test.failAt}
			service := NewService(vault, AllowAllBrokerCredentials{}, emitter, test.durable)
			if _, err := service.RequestExact(context.Background(), session, Request{CredentialID: "aws/development", Reason: test.reason}); err == nil {
				t.Fatal("credential request succeeded")
			}
		})
	}
}

func TestSessionsAuthenticateAndExpire(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	sessions := NewSessions()
	sessions.now = func() time.Time { return now }
	token, _, err := sessions.Register(Session{ID: "session-1"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := sessions.Lookup(token); !ok || got.ID != "session-1" {
		t.Fatalf("Lookup() = %#v, %v", got, ok)
	}
	if _, ok := sessions.Lookup("wrong"); ok {
		t.Fatal("wrong token authenticated")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := sessions.Lookup(token); ok {
		t.Fatal("expired token authenticated")
	}
}
