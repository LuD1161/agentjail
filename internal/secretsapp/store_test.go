package secretsapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStoreSetGet verifies that a secret can be stored and retrieved.
func TestStoreSetGet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")
	store, err := NewStore(dir, keyPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Set("aws/prod", `{"role_arn":"arn:aws:iam::123:role/test","access_key":"AKIA...","secret_key":"secret"}`); err != nil {
		t.Fatalf("Set: %v", err)
	}

	value, err := store.Get("aws/prod")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(value, "role_arn") {
		t.Errorf("Get returned unexpected value: %q", value)
	}
}

// TestStoreEncryptedAtRest verifies that the stored file is not plaintext.
func TestStoreEncryptedAtRest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")
	store, err := NewStore(dir, keyPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	secret := `{"access_key":"AKIATESTKEY123","secret_key":"supersecret123"}`
	if err := store.Set("aws/prod", secret); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "aws/prod"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), "supersecret123") {
		t.Error("secret is stored in plaintext — not encrypted at rest!")
	}
	if strings.Contains(string(raw), "AKIATESTKEY123") {
		t.Error("access key is stored in plaintext — not encrypted at rest!")
	}
}

// TestStoreList verifies that List returns secret names without values.
func TestStoreList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")
	store, err := NewStore(dir, keyPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	for _, name := range []string{"aws/prod", "pg/staging", "redis/dev"} {
		if err := store.Set(name, `{"x":"y"}`); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}

	names, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("expected 3 secrets, got %d: %v", len(names), names)
	}
}

// TestStoreDelete verifies that a secret can be deleted.
func TestStoreDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")
	store, err := NewStore(dir, keyPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Set("aws/prod", `{"x":"y"}`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Delete("aws/prod"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("aws/prod"); !os.IsNotExist(err) {
		t.Fatalf("expected ErrNotExist after delete, got: %v", err)
	}
}

// TestStoreKeyPersistence verifies that the same key is used across store instances.
func TestStoreKeyPersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")

	store1, err := NewStore(dir, keyPath)
	if err != nil {
		t.Fatalf("NewStore 1: %v", err)
	}
	if err := store1.Set("test", "secret-value"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	store2, err := NewStore(dir, keyPath)
	if err != nil {
		t.Fatalf("NewStore 2: %v", err)
	}
	value, err := store2.Get("test")
	if err != nil {
		t.Fatalf("Get from store2: %v", err)
	}
	if value != "secret-value" {
		t.Errorf("expected 'secret-value', got %q", value)
	}
}

// TestStoreKeyFilePermissions verifies the key file is 0600.
func TestStoreKeyFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")
	if _, err := NewStore(dir, keyPath); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o; want 0600", info.Mode().Perm())
	}
}

// TestStoreDirPermissions verifies the store directory is 0700.
func TestStoreDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	keyPath := filepath.Join(filepath.Dir(dir), "test.key")
	if _, err := NewStore(dir, keyPath); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("store dir mode = %o; want 0700", info.Mode().Perm())
	}
}

// TestValidateName verifies that secret names are validated.
func TestValidateName(t *testing.T) {
	valid := []string{"aws/prod", "pg/staging", "redis_dev", "my-secret", "a"}
	for _, name := range valid {
		if err := validateName(name); err != nil {
			t.Errorf("validateName(%q) = %v; want nil", name, err)
		}
	}
	invalid := []string{"", "..", "a/../b", "a\x00b"}
	for _, name := range invalid {
		if err := validateName(name); err == nil {
			t.Errorf("validateName(%q) = nil; want error", name)
		}
	}
}

// TestEncryptDecrypt verifies the encrypt/decrypt round-trip.
func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []string{
		"hello world",
		`{"access_key":"AKIA...","secret_key":"secret"}`,
		"",
		strings.Repeat("a", 4096),
	}

	for _, plaintext := range tests {
		ciphertext, err := encrypt(key, []byte(plaintext))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		decrypted, err := decrypt(key, ciphertext)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if string(decrypted) != plaintext {
			t.Errorf("decrypt mismatch: got %q, want %q", string(decrypted), plaintext)
		}
	}
}

// TestDecryptWrongKey verifies that decryption with the wrong key fails.
func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	ciphertext, err := encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decrypt(key2, ciphertext); err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}
