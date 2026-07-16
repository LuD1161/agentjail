//go:build linux

package keyring

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// openBound is the wall-clock ceiling Open() must respect. A recorder stalls on
// every captured request if this is exceeded, so it is a hard assertion, not a
// nicety. See ADR 0096-linux-secret-service.
const openBound = 2 * dbusDeadline

// Guards the hang: a locked collection, a wedged bus, or an absent one must all
// resolve within the deadline. secret-tool hangs forever on exactly this host.
func TestOpenIsBoundedAndTyped(t *testing.T) {
	stageKEKHome(t)
	start := time.Now()
	k, err := Open()
	elapsed := time.Since(start)

	if elapsed > openBound {
		t.Fatalf("Open() took %s, over the %s bound: a recorder would stall", elapsed, openBound)
	}
	if err == nil {
		t.Logf("Open selected %s (tier %s) in %s", k.Backend(), k.Tier(), elapsed)
		return
	}
	if !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("want ErrNoKeychain, got %v", err)
	}
	if k != nil {
		t.Fatal("Open returned a Keyring alongside an error")
	}
	t.Logf("no keychain in %s: %v", elapsed, err)
}

// The ladder is Secret Service then file KEK; the ephemeral "session"
// collection or a process-lifetime key would be plan 014 §5's rejected option
// C, arrived at by accident. See ADR 0097-linux-kek-fallback.
func TestOpenSelectsALadderRungNeverMemory(t *testing.T) {
	stageKEKHome(t)
	k, err := Open()
	if err != nil {
		t.Skipf("no keychain and no file KEK on this host: %v", err)
	}
	switch k.Backend() {
	case "linux-secret-service":
		if k.Tier() != TierKeychain {
			t.Fatalf("secret service reported tier %q", k.Tier())
		}
	case "file-kek":
		if k.Tier() != TierFileKEK {
			t.Fatalf("file KEK reported tier %q", k.Tier())
		}
	default:
		t.Fatalf("Open() selected %q, which is not a rung of the ladder", k.Backend())
	}
}

// A locked collection must land on the file KEK, not on plaintext bodies.
func TestLockedKeychainFallsBackToFileKEK(t *testing.T) {
	stageKEKHome(t)
	if _, err := openSecretService(); !errors.Is(err, ErrNoKeychain) {
		t.Skipf("this host has an unlocked Secret Service: %v", err)
	}
	s, err := openOSStore()
	if err != nil {
		t.Fatalf("openOSStore: %v", err)
	}
	if s.Tier() != TierFileKEK {
		t.Fatalf("fell back to %q (tier %q), want the file KEK", s.Name(), s.Tier())
	}
}

// A real round-trip through a live Secret Service. Opt-in: it writes to the
// caller's actual keychain, and CI has no bus. See ADR 0096-linux-secret-service.
func TestSecretServiceRoundTrip(t *testing.T) {
	if os.Getenv("AGENTJAIL_KEYRING_E2E") != "1" {
		t.Skip("set AGENTJAIL_KEYRING_E2E=1 to exercise a real Secret Service")
	}
	s, err := openOSStore()
	if err != nil {
		t.Fatalf("openOSStore: %v", err)
	}
	if s.Name() != "linux-secret-service" {
		t.Fatalf("backend is %q", s.Name())
	}

	// Absent items must be errNotFound, or Keyring.current() would fail instead
	// of minting the first KEK.
	if _, err := s.Get("body-kek/e2e-absent"); !errors.Is(err, errNotFound) {
		t.Fatalf("absent item: want errNotFound, got %v", err)
	}

	k := New(s)
	dek := testDEK(t)
	aad := []byte("bodies/e2e/body-1.raw.enc")

	id, wrapped, err := k.Wrap(dek, aad)
	if err != nil {
		t.Fatalf("Wrap through Secret Service: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped blob contains the plaintext DEK")
	}

	// A second Keyring over a fresh connection proves the KEK actually persisted
	// in the daemon, rather than living in this process.
	s2, err := openOSStore()
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := New(s2).Unwrap(id, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap on a fresh connection: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, dek)
	}

	if _, err := New(s2).Unwrap(id, wrapped, []byte("bodies/e2e/body-2.raw.enc")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("wrong aad through a real KEK: want ErrUnwrap, got %v", err)
	}
}

// gnome-keyring's ephemeral "session" collection is unlocked and would satisfy
// every other assertion here while giving a KEK that dies with the login
// session -- plan 014 §5's rejected option C, arrived at by accident.
func TestSecretServiceUsesPersistentCollection(t *testing.T) {
	if os.Getenv("AGENTJAIL_KEYRING_E2E") != "1" {
		t.Skip("set AGENTJAIL_KEYRING_E2E=1 to exercise a real Secret Service")
	}
	s, err := openOSStore()
	if err != nil {
		t.Fatalf("openOSStore: %v", err)
	}
	if got := s.(*secretService).coll.Path(); strings.HasSuffix(string(got), "/session") {
		t.Fatalf("resolved the ephemeral collection %s: bodies would outlive their KEK", got)
	}
}

// Set must overwrite in place; without replace=true the daemon accumulates
// duplicate items and Get starts returning a stale KEK.
func TestSecretServiceSetReplaces(t *testing.T) {
	if os.Getenv("AGENTJAIL_KEYRING_E2E") != "1" {
		t.Skip("set AGENTJAIL_KEYRING_E2E=1 to exercise a real Secret Service")
	}
	s, err := openOSStore()
	if err != nil {
		t.Fatalf("openOSStore: %v", err)
	}
	const account = "body-kek/e2e-replace"
	// A real keychain outlives the test binary, so leftovers from an earlier run
	// would decide this test's outcome instead of the code under test.
	purgeItems(t, s.(*secretService), account)
	t.Cleanup(func() { purgeItems(t, s.(*secretService), account) })

	for _, want := range [][]byte{bytes.Repeat([]byte{0xA1}, KEKSize), bytes.Repeat([]byte{0xB2}, KEKSize)} {
		if err := s.Set(account, want); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := s.Get(account)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Get returned %x, want %x", got, want)
		}
	}

	// Get reads items[0] and the daemon does not promise an order, so a value
	// check alone passes by luck; the duplicate itself is the bug.
	if n := countItems(t, s.(*secretService), account); n != 1 {
		t.Fatalf("account %s has %d items after two Sets: a stale KEK can win the next Get", account, n)
	}
}

func purgeItems(t *testing.T, s *secretService, account string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dbusDeadline)
	defer cancel()
	var items []dbus.ObjectPath
	if err := s.coll.CallWithContext(ctx, collIface+".SearchItems", 0, attrsFor(account)).Store(&items); err != nil {
		t.Fatalf("SearchItems: %v", err)
	}
	for _, it := range items {
		var prompt dbus.ObjectPath
		if err := s.conn.Object(secretsName, it).CallWithContext(ctx, itemIface+".Delete", 0).Store(&prompt); err != nil {
			t.Fatalf("Delete %s: %v", it, err)
		}
	}
}

func countItems(t *testing.T, s *secretService, account string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dbusDeadline)
	defer cancel()
	var items []dbus.ObjectPath
	if err := s.coll.CallWithContext(ctx, collIface+".SearchItems", 0, attrsFor(account)).Store(&items); err != nil {
		t.Fatalf("SearchItems: %v", err)
	}
	return len(items)
}
