//go:build darwin

package keyring

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// securityBin is stock on macOS; unlike Linux's secret-tool it is never absent.
const securityBin = "/usr/bin/security"

// keychainDeadline bounds every call: a recorder must not block a captured
// request on a keychain UI prompt (plan 014 §5, operational semantics).
const keychainDeadline = 5 * time.Second

// NAMED EXCEPTION (ADR 0034 rule 3): plan 014 §1 notes Keychain items can carry
// ACLs, user-presence, and code-signing constraints -- genuinely stronger than
// Secret Service. None are expressed here: they need a signed binary and the
// Security.framework API, not the security(1) CLI. Left unimplemented, not
// silently omitted.
//
// NAMED EXCEPTION: the secret crosses on argv (security(1) has no stdin form).
// It is hex so it is argv-safe. macOS restricts argv reads to the same uid,
// which already has keychain access, so this widens nothing -- but it is a real
// difference from a Security.framework backend and is recorded, not hidden.
type darwinKeychain struct{}

func openOSStore() (Store, error) {
	if _, err := exec.LookPath(securityBin); err != nil {
		return nil, fmt.Errorf("%w: %s is absent", ErrNoKeychain, securityBin)
	}
	return darwinKeychain{}, nil
}

func (darwinKeychain) Name() string { return "darwin-keychain" }

func (darwinKeychain) Tier() Tier { return TierKeychain }

func (darwinKeychain) Get(account string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keychainDeadline)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityBin,
		"find-generic-password", "-s", ServiceName, "-a", account, "-w")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: keychain did not answer within %s", ErrNoKeychain, keychainDeadline)
		}
		// security(1) exits 44 for "item not found"; anything else is a real fault.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return nil, fmt.Errorf("%w: %s", errNotFound, account)
		}
		return nil, fmt.Errorf("keyring: find-generic-password %s: %w: %s", account, err, strings.TrimSpace(errOut.String()))
	}
	raw, err := hex.DecodeString(strings.TrimSpace(out.String()))
	if err != nil {
		return nil, fmt.Errorf("%w: item %s is not hex", ErrCorruptKEK, account)
	}
	return raw, nil
}

func (darwinKeychain) Set(account string, secret []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), keychainDeadline)
	defer cancel()

	// -U updates in place; without it a second Set fails with "already exists".
	cmd := exec.CommandContext(ctx, securityBin,
		"add-generic-password", "-s", ServiceName, "-a", account,
		"-w", hex.EncodeToString(secret), "-U")
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%w: keychain did not answer within %s", ErrNoKeychain, keychainDeadline)
		}
		return fmt.Errorf("keyring: add-generic-password %s: %w: %s", account, err, strings.TrimSpace(errOut.String()))
	}
	return nil
}
