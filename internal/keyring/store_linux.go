//go:build linux

package keyring

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	secretsName = "org.freedesktop.secrets"
	secretsPath = dbus.ObjectPath("/org/freedesktop/secrets")
	svcIface    = "org.freedesktop.Secret.Service"
	collIface   = "org.freedesktop.Secret.Collection"
	itemIface   = "org.freedesktop.Secret.Item"
	promptIface = "org.freedesktop.Secret.Prompt"
	propsIface  = "org.freedesktop.DBus.Properties"

	// noObject is Secret Service's "no such object": a "/" prompt means no
	// prompt is needed, and a "/" alias means the collection does not exist.
	noObject = dbus.ObjectPath("/")

	// plainAlgo transfers secrets unencrypted over the bus. The bus is a
	// same-uid AF_UNIX socket, and same-uid is explicitly not our threat model
	// (see this package's doc comment), so the DH handshake would buy nothing.
	plainAlgo = "plain"
)

// dbusDeadline bounds every Secret Service call: a recorder must never stall a
// captured request on a bus that is absent, wedged, or awaiting a UI prompt.
// See ADR 0096-linux-secret-service.
const dbusDeadline = 3 * time.Second

// secretService is a Store over the Secret Service D-Bus API (gnome-keyring,
// kwallet). It is a dumb item store: KEK naming, sizing, and the wrap format
// stay in keyring.go. See ADR 0034-platform-backend-shared-contract.
type secretService struct {
	conn *dbus.Conn
	svc  dbus.BusObject
	// coll is the persistent default collection, resolved once and never the
	// ephemeral "session" one -- that would be plan 014 §5's rejected option C.
	coll    dbus.BusObject
	session dbus.ObjectPath
}

// dbusSecret is the Secret Service wire struct for a secret value.
type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func openOSStore() (Store, error) {
	// Auth and Hello do bus I/O with no context, so bound the whole dial rather
	// than only the calls that take one. A hang here is a stalled recorder.
	type result struct {
		s   *secretService
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := dialSecretService()
		ch <- result{s, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.s, nil
	case <-time.After(dbusDeadline):
		// A late dial must not leak its connection.
		go func() {
			if r := <-ch; r.s != nil {
				r.s.conn.Close()
			}
		}()
		return nil, fmt.Errorf("%w: secret service did not answer within %s", ErrNoKeychain, dbusDeadline)
	}
}

func dialSecretService() (*secretService, error) {
	// NoAutoStartup: the autolaunch path shells out to dbus-launch and spawns a
	// daemon. A recorder discovers a bus, it does not create one.
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return nil, fmt.Errorf("%w: no session bus: %v", ErrNoKeychain, err)
	}
	if err := conn.Auth(nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: session bus auth: %v", ErrNoKeychain, err)
	}
	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: session bus hello: %v", ErrNoKeychain, err)
	}

	s := &secretService{conn: conn, svc: conn.Object(secretsName, secretsPath)}
	if err := s.resolve(); err != nil {
		conn.Close()
		return nil, err
	}
	return s, nil
}

// resolve finds the unlocked persistent collection and opens a transfer
// session. Every failure here is ErrNoKeychain: no service, no default
// collection, locked with no way to unlock, or the bus refusing us.
func (s *secretService) resolve() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbusDeadline)
	defer cancel()

	var collPath dbus.ObjectPath
	if err := s.svc.CallWithContext(ctx, svcIface+".ReadAlias", 0, "default").Store(&collPath); err != nil {
		return fmt.Errorf("%w: secret service unreachable: %v", ErrNoKeychain, err)
	}
	if collPath == noObject {
		return fmt.Errorf("%w: no default collection", ErrNoKeychain)
	}
	s.coll = s.conn.Object(secretsName, collPath)

	if err := s.unlock(ctx, collPath); err != nil {
		return err
	}

	var output dbus.Variant
	var sessPath dbus.ObjectPath
	if err := s.svc.CallWithContext(ctx, svcIface+".OpenSession", 0, plainAlgo, dbus.MakeVariant("")).
		Store(&output, &sessPath); err != nil {
		return fmt.Errorf("%w: open session: %v", ErrNoKeychain, err)
	}
	s.session = sessPath
	return nil
}

// unlock refuses to drive a prompt: a headless host would block on a dialog no
// one can answer (this is why secret-tool hangs there). Dismiss and report the
// keychain absent, per plan 014 §5's prompt/hang deadline.
func (s *secretService) unlock(ctx context.Context, collPath dbus.ObjectPath) error {
	var locked bool
	if err := s.coll.CallWithContext(ctx, propsIface+".Get", 0, collIface, "Locked").Store(&locked); err != nil {
		return fmt.Errorf("%w: read lock state: %v", ErrNoKeychain, err)
	}
	if !locked {
		return nil
	}

	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := s.svc.CallWithContext(ctx, svcIface+".Unlock", 0, []dbus.ObjectPath{collPath}).
		Store(&unlocked, &prompt); err != nil {
		return fmt.Errorf("%w: unlock: %v", ErrNoKeychain, err)
	}
	if prompt != noObject {
		s.dismiss(ctx, prompt)
		// Locked, not absent: a keychain is here and the advice differs.
		// See AGE-254.
		return fmt.Errorf("%w: default collection is locked and unlocking needs an interactive prompt", ErrKeychainLocked)
	}
	for _, p := range unlocked {
		if p == collPath {
			return nil
		}
	}
	return fmt.Errorf("%w: default collection stayed locked", ErrNoKeychain)
}

func (s *secretService) dismiss(ctx context.Context, prompt dbus.ObjectPath) {
	_ = s.conn.Object(secretsName, prompt).CallWithContext(ctx, promptIface+".Dismiss", 0).Err
}

func (s *secretService) Name() string { return "linux-secret-service" }

// attrsFor names one item. It mirrors the darwin backend's -s/-a pair; the
// account strings themselves come from the contract, never built here.
func attrsFor(account string) map[string]string {
	return map[string]string{"service": ServiceName, "account": account}
}

func (s *secretService) Get(account string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbusDeadline)
	defer cancel()

	// Scoped to the default collection: Service.SearchItems would also sweep the
	// ephemeral "session" collection and could shadow a persistent KEK.
	var items []dbus.ObjectPath
	if err := s.coll.CallWithContext(ctx, collIface+".SearchItems", 0, attrsFor(account)).Store(&items); err != nil {
		return nil, fmt.Errorf("%w: search %s: %v", ErrNoKeychain, account, err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: %s", errNotFound, account)
	}

	var sec dbusSecret
	if err := s.conn.Object(secretsName, items[0]).
		CallWithContext(ctx, itemIface+".GetSecret", 0, s.session).Store(&sec); err != nil {
		return nil, fmt.Errorf("%w: get secret %s: %v", ErrNoKeychain, account, err)
	}
	return sec.Value, nil
}

func (s *secretService) Set(account string, secret []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbusDeadline)
	defer cancel()

	props := map[string]dbus.Variant{
		itemIface + ".Label":      dbus.MakeVariant(ServiceName + ": " + account),
		itemIface + ".Attributes": dbus.MakeVariant(attrsFor(account)),
	}
	val := dbusSecret{
		Session:     s.session,
		Value:       secret,
		ContentType: "application/octet-stream",
	}

	var item, prompt dbus.ObjectPath
	// replace=true: the contract's Set must overwrite, not accumulate duplicates.
	if err := s.coll.CallWithContext(ctx, collIface+".CreateItem", 0, props, val, true).
		Store(&item, &prompt); err != nil {
		return fmt.Errorf("%w: create item %s: %v", ErrNoKeychain, account, err)
	}
	if prompt != noObject {
		s.dismiss(ctx, prompt)
		return fmt.Errorf("%w: storing %s needs an interactive prompt", ErrNoKeychain, account)
	}
	if item == noObject {
		return fmt.Errorf("%w: secret service stored no item for %s", ErrNoKeychain, account)
	}
	return nil
}
