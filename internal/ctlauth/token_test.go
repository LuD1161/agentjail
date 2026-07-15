package ctlauth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func tempHome(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ct")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	t.Setenv("HOME", d)
	return d
}

func TestEnsure_CreatesOnceAndIsStable(t *testing.T) {
	tempHome(t)

	first, err := Ensure()
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(first) != tokenBytes*2 {
		t.Errorf("expected %d hex chars, got %d", tokenBytes*2, len(first))
	}

	// A second Ensure must NOT mint a new token: that would silently invalidate
	// every client already holding the first one.
	second, err := Ensure()
	if err != nil {
		t.Fatalf("Ensure (2nd): %v", err)
	}
	if first != second {
		t.Error("Ensure must be idempotent — a second call reminted the token")
	}
}

func TestEnsure_FileIsOwnerOnly(t *testing.T) {
	tempHome(t)
	if _, err := Ensure(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(TokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("token mode = %o, want 600", perm)
	}
}

// TestEnsure_ConcurrentStartersAgree: two servers starting together must end up
// with the same token, or clients authenticate against one and fail the other.
func TestEnsure_ConcurrentStartersAgree(t *testing.T) {
	tempHome(t)

	const n = 8
	var (
		mu   sync.Mutex
		toks []string
		wg   sync.WaitGroup
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := Ensure()
			if err != nil {
				return
			}
			mu.Lock()
			toks = append(toks, tok)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(toks) != n {
		t.Fatalf("expected %d successful Ensure calls, got %d", n, len(toks))
	}
	for _, tok := range toks {
		if tok != toks[0] {
			t.Fatal("concurrent Ensure calls produced different tokens")
		}
	}
}

func TestLoad_MissingIsErrNoToken(t *testing.T) {
	tempHome(t)
	if _, err := Load(); !errors.Is(err, ErrNoToken) {
		t.Errorf("expected ErrNoToken, got %v", err)
	}
}

func TestLoad_RoundTripsEnsure(t *testing.T) {
	tempHome(t)
	want, err := Ensure()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Load = %q, want %q", got, want)
	}
}

// TestLoad_UnreadableTokenFails is the property the whole boundary rests on: if
// the process cannot READ the token (which is what Landlock enforces for the
// sandboxed agent), it cannot obtain one.
func TestLoad_UnreadableTokenFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	tempHome(t)
	if _, err := Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(TokenPath(), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(TokenPath(), 0o600) })

	if _, err := Load(); err == nil {
		t.Error("expected Load to fail when the token file is unreadable")
	}
}

func TestValid(t *testing.T) {
	tok := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		got, want string
		ok        bool
	}{
		{"match", tok, tok, true},
		{"mismatch", strings.Repeat("b", 64), tok, false},
		{"empty got", "", tok, false},
		{"empty want fails closed", tok, "", false},
		{"both empty fails closed", "", "", false},
		{"prefix is not enough", tok[:32], tok, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Valid(tc.got, tc.want); got != tc.ok {
				t.Errorf("Valid(%q, %q) = %v, want %v", tc.got, tc.want, got, tc.ok)
			}
		})
	}
}

func TestTokenPathForHome(t *testing.T) {
	got := TokenPathForHome("/home/u")
	want := filepath.Join("/home/u", ".agentjail", TokenFileName)
	if got != want {
		t.Errorf("TokenPathForHome = %q, want %q", got, want)
	}
}
