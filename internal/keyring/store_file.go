package keyring

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// The file KEK is the Linux fallback when Secret Service is locked or absent:
// bodies are always encrypted, never silently recorded in the clear.
// See ADR 0097-linux-kek-fallback.
const (
	kekFileMode os.FileMode = 0o600
	kekDirMode  os.FileMode = 0o700
	kekFileName             = "kek"
	kekLockName             = "kek.lock"
	kekDirName              = "agentjail"
)

// Errors this backend refuses on. A wrong-mode or symlinked KEK is a bug to
// report, never something to accept silently.
var (
	// ErrKEKFilePerms means the KEK file exists with permissions other than
	// 0600, so some other principal may already hold the key.
	ErrKEKFilePerms = errors.New("keyring: kek file has unsafe permissions")

	// ErrKEKFileSymlink means a symlink sits at the KEK path or its directory,
	// which would re-point reads and writes outside our control.
	ErrKEKFileSymlink = errors.New("keyring: kek path is a symlink")

	// ErrKEKFileShape means the KEK file is not the regular file / JSON object
	// this backend writes.
	ErrKEKFileShape = errors.New("keyring: kek file is not a valid kek store")
)

// KEKFilePath reports where the file KEK lives: $XDG_CONFIG_HOME/agentjail/kek,
// defaulting to ~/.config/agentjail/kek. Exported so doctor and the shield can
// name the path without rebuilding it. See ADR 0097-linux-kek-fallback.
func KEKFilePath() (string, error) {
	dir, err := kekDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, kekFileName), nil
}

func kekDirPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, kekDirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("keyring: locate home: %w", err)
	}
	return filepath.Join(home, ".config", kekDirName), nil
}

// kekFileDoc is the on-disk shape. Store holds many named items, so one file
// carries a map rather than a bare key.
type kekFileDoc struct {
	Items map[string]string `json:"items"`
}

// fileStore is a Store over a single 0600 JSON file.
type fileStore struct {
	path     string
	lockPath string
	// held is non-nil while this store owns the mint lock, so a Set inside a
	// held lock does not deadlock re-acquiring it.
	held atomic.Pointer[os.File]
}

// OpenFileStore opens (creating the directory for) the file KEK store.
func OpenFileStore() (Store, error) {
	dir, err := kekDirPath()
	if err != nil {
		return nil, err
	}
	if err := prepareKEKDir(dir); err != nil {
		return nil, err
	}
	f := &fileStore{
		path:     filepath.Join(dir, kekFileName),
		lockPath: filepath.Join(dir, kekLockName),
	}
	if _, err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

// prepareKEKDir makes the directory 0700 and refuses a symlinked one. umask does
// not apply to the mode asserted afterwards, so chmod and verify rather than
// trusting MkdirAll's argument.
func prepareKEKDir(dir string) error {
	if err := os.MkdirAll(dir, kekDirMode); err != nil {
		return fmt.Errorf("keyring: mkdir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("keyring: stat %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrKEKFileSymlink, dir)
	}
	if err := os.Chmod(dir, kekDirMode); err != nil {
		return fmt.Errorf("keyring: chmod %s: %w", dir, err)
	}
	fi, err = os.Stat(dir)
	if err != nil {
		return fmt.Errorf("keyring: stat %s: %w", dir, err)
	}
	if fi.Mode().Perm() != kekDirMode {
		return fmt.Errorf("%w: %s is %#o, want %#o", ErrKEKFilePerms, dir, fi.Mode().Perm(), kekDirMode)
	}
	return nil
}

func (f *fileStore) Name() string { return "file-kek" }

func (f *fileStore) Tier() Tier { return TierFileKEK }

func (f *fileStore) Get(account string) ([]byte, error) {
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	enc, ok := doc.Items[account]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errNotFound, account)
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("%w: item %s: %v", ErrKEKFileShape, account, err)
	}
	return raw, nil
}

func (f *fileStore) Set(account string, secret []byte) error {
	if f.held.Load() != nil {
		return f.set(account, secret)
	}
	unlock, err := f.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	return f.set(account, secret)
}

func (f *fileStore) set(account string, secret []byte) error {
	doc, err := f.load()
	if err != nil {
		return err
	}
	doc.Items[account] = base64.StdEncoding.EncodeToString(secret)
	return f.save(doc)
}

// Lock serializes mint across processes and goroutines. See ADR 0097-linux-kek-fallback.
func (f *fileStore) Lock() (func(), error) {
	lf, err := os.OpenFile(f.lockPath, os.O_CREATE|os.O_RDWR, kekFileMode)
	if err != nil {
		return nil, fmt.Errorf("keyring: open lock %s: %w", f.lockPath, err)
	}
	if err := lockFile(lf); err != nil {
		lf.Close()
		return nil, fmt.Errorf("keyring: lock %s: %w", f.lockPath, err)
	}
	f.held.Store(lf)
	return func() {
		f.held.Store(nil)
		_ = unlockFile(lf)
		_ = lf.Close()
	}, nil
}

// guard refuses a symlinked or wrong-mode KEK file before it is read or
// replaced. A 0644 kek is a bug, not something to accept.
func (f *fileStore) guard() error {
	fi, err := os.Lstat(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("keyring: stat %s: %w", f.path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrKEKFileSymlink, f.path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrKEKFileShape, f.path)
	}
	if fi.Mode().Perm() != kekFileMode {
		return fmt.Errorf("%w: %s is %#o, want %#o", ErrKEKFilePerms, f.path, fi.Mode().Perm(), kekFileMode)
	}
	return nil
}

func (f *fileStore) load() (*kekFileDoc, error) {
	if err := f.guard(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return &kekFileDoc{Items: map[string]string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keyring: read %s: %w", f.path, err)
	}
	var doc kekFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKEKFileShape, f.path, err)
	}
	if doc.Items == nil {
		doc.Items = map[string]string{}
	}
	return &doc, nil
}

// save writes via a temp file in the same directory and renames: a crash must
// never leave a truncated kek.
func (f *fileStore) save(doc *kekFileDoc) error {
	if err := f.guard(); err != nil {
		return err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("keyring: encode kek file: %w", err)
	}
	tmp, err := f.createTemp()
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("keyring: write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("keyring: sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keyring: close %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), f.path); err != nil {
		return fmt.Errorf("keyring: rename onto %s: %w", f.path, err)
	}
	return nil
}

// createTemp opens an exclusive 0600 temp file beside the KEK and verifies the
// mode: umask does not apply to the mode asserted afterwards.
func (f *fileStore) createTemp() (*os.File, error) {
	tmp, err := os.CreateTemp(filepath.Dir(f.path), "."+kekFileName+"-*")
	if err != nil {
		return nil, fmt.Errorf("keyring: temp file: %w", err)
	}
	if err := tmp.Chmod(kekFileMode); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("keyring: chmod %s: %w", tmp.Name(), err)
	}
	fi, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("keyring: stat %s: %w", tmp.Name(), err)
	}
	if fi.Mode().Perm() != kekFileMode {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("%w: %s is %#o, want %#o", ErrKEKFilePerms, tmp.Name(), fi.Mode().Perm(), kekFileMode)
	}
	return tmp, nil
}
