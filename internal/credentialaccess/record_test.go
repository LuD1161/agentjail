package credentialaccess

import (
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/credentialtools"
)

const testAWSMaterial = `{"access_key_id":"AKIATEST","secret_access_key":"secret","region":"us-east-1"}`

func TestRecordRoundTripSeparatesMetadataFromMaterial(t *testing.T) {
	t.Parallel()
	record, err := NewRecord(credentialtools.ToolAWS, testAWSMaterial, "Development", "111122223333", "")
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
	descriptor := Describe("aws/development", decoded)
	if descriptor.Account != "111122223333" || descriptor.Label != "Development" || descriptor.Kind != "access_key" {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	encodedDescriptor := strings.Join([]string{descriptor.Label, descriptor.Account, descriptor.Kind}, " ")
	if strings.Contains(encodedDescriptor, "AKIATEST") || strings.Contains(encodedDescriptor, "secret") {
		t.Fatal("descriptor exposed credential material")
	}
}

func TestDecodeRejectsMalformedRecognizedRecord(t *testing.T) {
	t.Parallel()
	_, recognized, err := Decode(`{"agentjail_credential_version":1,"metadata":{"tool":"aws","kind":"token"},"material":"x"}`)
	if !recognized || err == nil {
		t.Fatalf("recognized=%v err=%v", recognized, err)
	}
}

func TestLegacyOnlyRecognizesTypedCredentialPrefixes(t *testing.T) {
	t.Parallel()
	if _, recognized, err := Legacy("aws/old", testAWSMaterial); err != nil || !recognized {
		t.Fatalf("legacy AWS recognized=%v err=%v", recognized, err)
	}
	if _, recognized, err := Legacy("MY_PROD_API_KEY", "secret"); err != nil || recognized {
		t.Fatalf("raw secret recognized=%v err=%v", recognized, err)
	}
}
