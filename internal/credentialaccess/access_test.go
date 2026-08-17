package credentialaccess

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
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
		return "", os.ErrNotExist
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

func encodedCredential(t *testing.T, label, tag, key string) string {
	t.Helper()
	record, err := NewRecord(Delivery{Env: []EnvVar{{Name: "ACCESS_TOKEN", Value: key}}}, label, []string{tag})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestListAndRequestExactArbitraryCredentialIDs(t *testing.T) {
	t.Parallel()
	vault := memoryVault{
		"aws-read-only-cred-dev":   encodedCredential(t, "Development", "dev", "dev-secret"),
		"slack-channel-read-token": encodedCredential(t, "Support channel", "slack", "slack-secret"),
		"untyped-secret":           "must-not-be-visible",
	}
	emitter := &eventEmitter{}
	service := NewService(vault, AllowAllBrokerCredentials{}, emitter, true)
	session := Session{ID: "session-1", Project: "/repo", Agent: "codex"}

	items, err := service.List(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "aws-read-only-cred-dev" || items[1].ID != "slack-channel-read-token" {
		t.Fatalf("items = %#v", items)
	}
	issuance, err := service.RequestExact(context.Background(), session, Request{CredentialID: "slack-channel-read-token"})
	if err != nil {
		t.Fatal(err)
	}
	if got := issuance.Delivery.Env[0].Value; got != "slack-secret" {
		t.Fatalf("issued value = %q", got)
	}
	for _, event := range emitter.events {
		for _, value := range event.Detail {
			if strings.Contains(value, "slack-secret") {
				t.Fatal("audit detail contains credential material")
			}
		}
	}
}

func TestRequestRequiresDurableAuditButReasonIsOptional(t *testing.T) {
	t.Parallel()
	vault := memoryVault{"credential": encodedCredential(t, "", "test", "secret")}
	session := Session{ID: "session-1", Project: "/repo", Agent: "codex"}
	if _, err := NewService(vault, AllowAllBrokerCredentials{}, &eventEmitter{}, true).RequestExact(context.Background(), session, Request{CredentialID: "credential"}); err != nil {
		t.Fatalf("optional reason rejected: %v", err)
	}
	for _, test := range []struct {
		name, reason, failAt string
		durable              bool
	}{
		{name: "oversized reason", reason: strings.Repeat("x", MaxReasonBytes+1), durable: true},
		{name: "audit unavailable"},
		{name: "request audit fails", durable: true, failAt: audit.CredentialAccessRequested},
		{name: "issued audit fails", durable: true, failAt: audit.CredentialAccessIssued},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := NewService(vault, AllowAllBrokerCredentials{}, &eventEmitter{failAt: test.failAt}, test.durable)
			if _, err := service.RequestExact(context.Background(), session, Request{CredentialID: "credential", Reason: test.reason}); err == nil {
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
