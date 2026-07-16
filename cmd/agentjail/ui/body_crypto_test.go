package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/mitm"
)

// keys mints a wrapper over an in-process keychain, so a test never reaches
// the real one. See ADR 0095-chunked-body-envelope.
func memKeys(t *testing.T) mitm.KeyWrapper {
	t.Helper()
	return keyring.New(keyring.NewMemoryStore())
}

// An encrypted body must stream back decrypted and byte-identical: the UI
// serving ciphertext as content is the bug this guards.
func TestEncryptedBodyStreamsDecrypted(t *testing.T) {
	dir := t.TempDir()
	kw := memKeys(t)
	want := bytes.Repeat([]byte("secret-payload-\x01\x02"), 4000)
	rel := writeBody(t, dir, "enc123", want, kw)

	// The bytes at rest must not be the plaintext, else this proves nothing.
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if bytes.Contains(raw, want[:64]) {
		t.Fatal("stored body is not encrypted; the test would pass vacuously")
	}

	base := liveServer(t, "127.0.0.1:9261", func(s *Server) {
		s.bodyDir, s.bodyKeys = dir, kw
	})
	resp, got := get(t, base+"/api/network/body?path="+rel, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("body -> %d, want 200; %.200s", resp.StatusCode, got)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decrypted body differs: got %d bytes, want %d", len(got), len(want))
	}
}

// A store holds plaintext and sealed bodies side by side, so the read path
// dispatches on the file, not on whether keys were configured.
func TestPlaintextBodyStreamsWithAndWithoutKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		keys func(*testing.T) mitm.KeyWrapper
	}{
		{"nil keys", "127.0.0.1:9262", func(*testing.T) mitm.KeyWrapper { return nil }},
		{"keys present", "127.0.0.1:9263", memKeys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			want := []byte(`{"hello":"plaintext world"}`)
			rel := writeBody(t, dir, "plain1", want, nil) // written in the clear

			base := liveServer(t, tc.addr, func(s *Server) {
				s.bodyDir, s.bodyKeys = dir, tc.keys(t)
			})
			resp, got := get(t, base+"/api/network/body?path="+rel, "", "")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("body -> %d, want 200; %.200s", resp.StatusCode, got)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("body = %q, want %q", got, want)
			}
		})
	}
}

// An encrypted body with no key must fail honestly. Dribbling ciphertext into
// a browser as if it were content is the failure mode.
// See ADR 0095-chunked-body-envelope.
func TestEncryptedBodyWithoutKeyFailsHonestly(t *testing.T) {
	dir := t.TempDir()
	plain := bytes.Repeat([]byte("TOP-SECRET-PLAINTEXT"), 100)
	rel := writeBody(t, dir, "enc456", plain, memKeys(t)) // key is discarded

	base := liveServer(t, "127.0.0.1:9264", func(s *Server) {
		s.bodyDir = dir
		s.bodyKeys = nil
		s.keysOnce.Do(func() {}) // never consult the host keychain
	})
	resp, got := get(t, base+"/api/network/body?path="+rel, "", "")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("sealed body served with no key: %d bytes of %q", len(got), got[:min(len(got), 40)])
	}
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	if bytes.Contains(got, plain[:20]) {
		t.Error("SECURITY: response leaked plaintext")
	}
	stored, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if bytes.Contains(got, stored[:64]) {
		t.Error("SECURITY: response carried raw ciphertext as content")
	}
	// The message must name the problem, not merely be non-200.
	if !bytes.Contains(got, []byte("encrypted")) {
		t.Errorf("error does not explain itself: %q", got)
	}
}

// A wrong key is no key: it must fail like an absent one, never emit bytes.
func TestEncryptedBodyWithWrongKeyFailsHonestly(t *testing.T) {
	dir := t.TempDir()
	rel := writeBody(t, dir, "enc789", []byte("sealed under key A"), memKeys(t))

	base := liveServer(t, "127.0.0.1:9265", func(s *Server) {
		s.bodyDir, s.bodyKeys = dir, memKeys(t) // a different keychain
	})
	resp, got := get(t, base+"/api/network/body?path="+rel, "", "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409; body=%.120s", resp.StatusCode, got)
	}
	if bytes.Contains(got, []byte("sealed under key A")) {
		t.Error("SECURITY: response leaked plaintext")
	}
}

// The UI must never write the transcript store: opening a body store on a
// path that is not there must create nothing. See ADR 0092 (D3).
func TestReadOnlyBodyStoreCreatesNoDirectory(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "not-there")

	rc, err := mitm.OpenBodyStoreReadOnly(missing, nil).Open("abc123/deadbeef.body")
	if err != nil {
		t.Fatalf("Open on a missing store: %v, want absent", err)
	}
	if rc != nil {
		t.Fatal("Open returned a reader for a store that does not exist")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("read-only open created %s (stat err = %v)", missing, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("read-only open created %d entries under the root: %v", len(entries), entries)
	}
}

// Serving a body must not mkdir a session dir for the reader. NewBodyStore
// created "bodies/uiread" on every request. See ADR 0092 (D3).
func TestServingABodyWritesNothing(t *testing.T) {
	dir := t.TempDir()
	rel := writeBody(t, dir, "sess01", []byte("content"), nil)

	before := dirEntries(t, dir)
	base := liveServer(t, "127.0.0.1:9266", func(s *Server) { s.bodyDir = dir })
	if resp, _ := get(t, base+"/api/network/body?path="+rel, "", ""); resp.StatusCode != 200 {
		t.Fatalf("body -> %d", resp.StatusCode)
	}
	if after := dirEntries(t, dir); !equalStrings(before, after) {
		t.Errorf("serving a body changed the store: before=%v after=%v", before, after)
	}
}

// bodyKeysTheFrontendReads are the exact JSON keys request-detail.tsx uses to
// locate a body. The panel read request_body/body_truncated -- keys no handler
// has ever emitted -- and showed "(empty body)" against a full store.
var bodyKeysTheFrontendReads = []string{"request_body_path", "response_body_path"}

// bodyKeysThatMustNotExist are inline-body keys. ADR 0092 (D1) chose files over
// BLOBs because bodies are unbounded; inlining one reintroduces the OOM.
var bodyKeysThatMustNotExist = []string{"request_body", "response_body", "body_truncated"}

// Decode into map[string]any, never the struct: decoding into the struct is
// what hid a renamed tag for months. See ADR 0092 (D1).
func TestBodyPathKeyContract(t *testing.T) {
	dir := t.TempDir()
	secret := "SENTINEL-NEVER-IN-JSON"
	rel := writeBody(t, dir, "abc123", []byte(secret), nil)

	ro := seedRows(t, mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages",
		URL: "https://api.anthropic.com/v1/messages", StatusCode: 200,
		RequestBodyPath: rel, ResponseBodyPath: rel,
	})
	base := liveServer(t, "127.0.0.1:9267", func(s *Server) {
		s.netStore, s.bodyDir = ro, dir
	})

	for _, route := range []string{"/api/requests?limit=5&offset=0", "/api/requests/1"} {
		resp, raw := get(t, base+route, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s -> %d: %.200s", route, resp.StatusCode, raw)
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("SECURITY: %s inlined body content into JSON", route)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s decode: %v", route, err)
		}
		row := doc
		if reqs, ok := doc["requests"].([]any); ok {
			if len(reqs) != 1 {
				t.Fatalf("%s: %d rows, want 1", route, len(reqs))
			}
			row, _ = reqs[0].(map[string]any)
		}
		for _, k := range bodyKeysTheFrontendReads {
			if got, ok := row[k]; !ok || got != rel {
				t.Errorf("%s: row[%q] = %v (present=%v), want %q", route, k, got, ok, rel)
			}
		}
		for _, k := range bodyKeysThatMustNotExist {
			if _, ok := row[k]; ok {
				t.Errorf("%s: row carries inline-body key %q; ADR 0092 D1 forbids it", route, k)
			}
		}
	}
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
