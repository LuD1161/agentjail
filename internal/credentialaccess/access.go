package credentialaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentialtools"
)

const MaxReasonBytes = 1024

// Vault is the encrypted-store seam consumed by credential access.
type Vault interface {
	List() ([]string, error)
	Get(string) (string, error)
}

// Session is the authenticated agent context bound to a broker capability.
type Session struct {
	ID      string
	Project string
	Agent   string
}

// Request asks for one exact discovered credential.
type Request struct {
	CredentialID ID
	Reason       string
}

// Issuance is direct static material prepared for the selected tool.
type Issuance struct {
	Credential Descriptor               `json:"credential"`
	Delivery   credentialtools.Delivery `json:"delivery"`
}

// Authorizer is the policy seam. The current OSS implementation authorizes
// every typed broker credential; later policy replaces it.
type Authorizer interface {
	Discover(Session, Descriptor) bool
	Authorize(Session, Descriptor, string) Approval
}

// AllowAllBrokerCredentials is the explicit current bootstrap posture.
type AllowAllBrokerCredentials struct{}

func (AllowAllBrokerCredentials) Discover(Session, Descriptor) bool { return true }
func (AllowAllBrokerCredentials) Authorize(Session, Descriptor, string) Approval {
	return ApprovalAutomatic
}

// Service owns discovery, exact selection, authorization, and audit ordering.
type Service struct {
	vault        Vault
	authorizer   Authorizer
	emitter      audit.Emitter
	durableAudit bool
	registry     credentialtools.Registry
}

func NewService(vault Vault, authorizer Authorizer, emitter audit.Emitter, durableAudit bool) *Service {
	return &Service{
		vault:        vault,
		authorizer:   authorizer,
		emitter:      emitter,
		durableAudit: durableAudit,
		registry:     credentialtools.DefaultRegistry(),
	}
}

// List returns only typed credential descriptors, never raw broker secrets.
func (s *Service) List(ctx context.Context, session Session, toolFilter credentialtools.Tool) ([]Descriptor, error) {
	names, err := s.vault.List()
	if err != nil {
		return nil, fmt.Errorf("list broker credentials: %w", err)
	}
	result := make([]Descriptor, 0, len(names))
	for _, name := range names {
		record, visible, err := s.loadRecord(ID(name))
		if err != nil {
			return nil, err
		}
		if !visible {
			continue
		}
		descriptor := Describe(ID(name), record)
		if toolFilter != "" && descriptor.Tool != toolFilter {
			continue
		}
		if s.authorizer.Discover(session, descriptor) {
			result = append(result, descriptor)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	_ = s.emitter.Emit(ctx, audit.Event{
		EventType: audit.CredentialListed,
		Entity:    string(toolFilter),
		Detail: map[string]string{
			"count":   fmt.Sprintf("%d", len(result)),
			"project": session.Project,
		},
		Actor:     session.Agent,
		SessionID: session.ID,
	})
	return result, nil
}

// RequestExact returns one exact credential. Every audit event before return
// is fail-closed; no material is returned when durable audit is unavailable.
func (s *Service) RequestExact(ctx context.Context, session Session, request Request) (Issuance, error) {
	reason, err := validateReason(request.Reason)
	if err != nil {
		s.emitDenied(ctx, session, request.CredentialID, err.Error())
		return Issuance{}, err
	}
	if request.CredentialID == "" {
		err := errors.New("credential_id is required")
		s.emitDenied(ctx, session, request.CredentialID, err.Error())
		return Issuance{}, err
	}
	if !s.durableAudit {
		return Issuance{}, errors.New("audit unavailable, refusing credential request")
	}
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType: audit.CredentialAccessRequested,
		Entity:    string(request.CredentialID),
		Detail: map[string]string{
			"reason":  reason,
			"project": session.Project,
		},
		Actor:     session.Agent,
		SessionID: session.ID,
	}); err != nil {
		return Issuance{}, fmt.Errorf("audit credential request: %w", err)
	}

	record, visible, err := s.loadRecord(request.CredentialID)
	if err != nil {
		s.emitDenied(ctx, session, request.CredentialID, "invalid_credential")
		return Issuance{}, err
	}
	if !visible {
		s.emitDenied(ctx, session, request.CredentialID, "not_found")
		return Issuance{}, fmt.Errorf("credential %q is not available", request.CredentialID)
	}
	descriptor := Describe(request.CredentialID, record)
	if !s.authorizer.Discover(session, descriptor) {
		s.emitDenied(ctx, session, request.CredentialID, "not_discoverable")
		return Issuance{}, fmt.Errorf("credential %q is not available", request.CredentialID)
	}
	approval := s.authorizer.Authorize(session, descriptor, reason)
	if approval != ApprovalAutomatic {
		s.emitDenied(ctx, session, request.CredentialID, "not_approved")
		return Issuance{}, fmt.Errorf("credential %q is not approved", request.CredentialID)
	}
	if err := s.emitRequired(ctx, audit.Event{
		EventType: audit.CredentialAccessApproved,
		Entity:    string(request.CredentialID),
		Detail:    requestDetail(session, descriptor, reason, "bootstrap_allow_all"),
		Actor:     session.Agent,
		SessionID: session.ID,
	}); err != nil {
		return Issuance{}, err
	}

	material, err := credentialtools.DecodeStatic(descriptor.Tool, record.Material)
	if err != nil {
		s.emitDenied(ctx, session, request.CredentialID, "invalid_material")
		return Issuance{}, fmt.Errorf("credential %q: %w", request.CredentialID, err)
	}
	adapter, err := s.registry.Resolve(descriptor.Tool)
	if err != nil {
		return Issuance{}, err
	}
	delivery, err := adapter.Present(material)
	if err != nil {
		s.emitDenied(ctx, session, request.CredentialID, "presentation_failed")
		return Issuance{}, err
	}
	detail := requestDetail(session, descriptor, reason, "bootstrap_allow_all")
	detail["fingerprint"] = fingerprint(record.Material)
	if err := s.emitRequired(ctx, audit.Event{
		EventType: audit.CredentialAccessIssued,
		Entity:    string(request.CredentialID),
		Detail:    detail,
		Actor:     session.Agent,
		SessionID: session.ID,
	}); err != nil {
		return Issuance{}, err
	}
	slog.Info("credential access issued",
		"credential_id", request.CredentialID,
		"tool", descriptor.Tool,
		"session_id", session.ID,
		"fingerprint", detail["fingerprint"],
	)
	return Issuance{Credential: descriptor, Delivery: delivery}, nil
}

func (s *Service) loadRecord(id ID) (Record, bool, error) {
	raw, err := s.vault.Get(string(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("load credential %q: %w", id, err)
	}
	record, recognized, err := Decode(raw)
	if err != nil {
		return Record{}, false, fmt.Errorf("credential %q: %w", id, err)
	}
	if recognized {
		return record, true, nil
	}
	return Legacy(id, raw)
}

func (s *Service) emitRequired(ctx context.Context, event audit.Event) error {
	if err := s.emitter.Emit(ctx, event); err != nil {
		return fmt.Errorf("audit %s: %w", event.EventType, err)
	}
	return nil
}

func (s *Service) emitDenied(ctx context.Context, session Session, id ID, outcome string) {
	_ = s.emitter.Emit(ctx, audit.Event{
		EventType: audit.CredentialAccessDenied,
		Entity:    string(id),
		Detail: map[string]string{
			"outcome": outcome,
			"project": session.Project,
		},
		Actor:     session.Agent,
		SessionID: session.ID,
	})
}

func requestDetail(session Session, descriptor Descriptor, reason, policy string) map[string]string {
	return map[string]string{
		"tool":    string(descriptor.Tool),
		"kind":    descriptor.Kind,
		"account": descriptor.Account,
		"context": descriptor.Context,
		"reason":  reason,
		"project": session.Project,
		"policy":  policy,
	}
}

func validateReason(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("reason is required")
	}
	if !utf8.ValidString(value) {
		return "", errors.New("reason must be valid UTF-8")
	}
	if len(value) > MaxReasonBytes {
		return "", fmt.Errorf("reason exceeds %d bytes", MaxReasonBytes)
	}
	for _, r := range value {
		if r < 0x20 && r != '\t' {
			return "", errors.New("reason contains a control character")
		}
	}
	return value, nil
}

func fingerprint(material string) string {
	sum := sha256.Sum256([]byte(material))
	return "sha256:" + hex.EncodeToString(sum[:8])
}
