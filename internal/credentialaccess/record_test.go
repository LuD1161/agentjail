package credentialaccess

import (
	"strings"
	"testing"
)

func TestRecordRoundTripSeparatesMetadataFromMaterial(t *testing.T) {
	t.Parallel()
	record, err := NewRecord(Delivery{Env: []EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", Value: "AKIATEST"},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: "secret"},
	}}, "Production read only", []string{"prod", "aws", "prod"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, recognized, err := Decode(raw)
	if err != nil || !recognized {
		t.Fatalf("Decode() = %#v, %v, %v", decoded, recognized, err)
	}
	descriptor := Describe("aws-read-only-cred-prod", decoded)
	if descriptor.Label != "Production read only" || strings.Join(descriptor.Tags, ",") != "aws,prod" {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	encodedDescriptor := descriptor.Label + strings.Join(descriptor.Tags, " ")
	if strings.Contains(encodedDescriptor, "AKIATEST") || strings.Contains(encodedDescriptor, "secret") {
		t.Fatal("descriptor exposed credential material")
	}
}

func TestDecodeHidesOldUnreleasedAndRawRecords(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"agentjail_credential_version":1,"metadata":{"tool":"aws","kind":"access_key"},"material":"x"}`,
		"plain-secret",
	} {
		if _, recognized, err := Decode(raw); err != nil || recognized {
			t.Fatalf("Decode(%q) recognized=%v err=%v", raw, recognized, err)
		}
	}
}

func TestDeliveryRejectsSessionControlEnvironment(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"PATH", "AGENTJAIL_CREDENTIAL_SESSION_TOKEN", "DYLD_INSERT_LIBRARIES", "HTTPS_PROXY", "SSH_AUTH_SOCK"} {
		if _, err := NewRecord(Delivery{Env: []EnvVar{{Name: name, Value: "x"}}}, "", nil); err == nil {
			t.Fatalf("security-sensitive environment %q was accepted", name)
		}
	}
}

func TestDeliveryRejectsDuplicateAndUnsafeBindings(t *testing.T) {
	t.Parallel()
	for _, delivery := range []Delivery{
		{Env: []EnvVar{{Name: "TOKEN", Value: "x"}, {Name: "TOKEN", Value: "y"}}},
		{Files: []SessionFile{{EnvVar: "CONFIG", Name: "../escape", Content: []byte("x")}}},
		{Env: []EnvVar{{Name: "bad-name", Value: "x"}}},
	} {
		if err := ValidateDelivery(delivery); err == nil {
			t.Fatalf("unsafe delivery accepted: %#v", delivery)
		}
	}
}
