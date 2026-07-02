package projectpolicy

import (
	"os"
	"path/filepath"
	"sort"

	"go.yaml.in/yaml/v3"
)

// TrustEntry is one trusted project overlay: its absolute path and the content
// hash that was approved. Both must match for the overlay to be applied.
type TrustEntry struct {
	Path        string `yaml:"path"`
	ContentHash string `yaml:"content_hash"`
}

// trustFile is the on-disk shape of ~/.agentjail/trusted.yaml.
type trustFile struct {
	Trusted []TrustEntry `yaml:"trusted"`
}

// TrustStore is the set of trusted project overlays, loaded from and saved to
// ~/.agentjail/trusted.yaml. It is keyed by overlay path -> approved hash.
type TrustStore struct {
	path    string
	entries map[string]string
}

// TrustStorePath returns the trust store path for a given ~/.agentjail dir.
func TrustStorePath(agentjailDir string) string {
	return filepath.Join(agentjailDir, TrustFileName)
}

// LoadTrustStore reads the trust store at path. A missing file is not an error
// (an empty store means nothing is trusted). A malformed file IS an error --
// callers should fail safe (treat overlays as untrusted) rather than guess.
func LoadTrustStore(path string) (*TrustStore, error) {
	ts := &TrustStore{path: path, entries: make(map[string]string)}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ts, nil
	}
	if err != nil {
		return nil, err
	}
	var tf trustFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, err
	}
	for _, e := range tf.Trusted {
		ts.entries[e.Path] = e.ContentHash
	}
	return ts, nil
}

// IsTrusted reports whether the overlay's path is trusted AND its current
// content hash matches the approved hash. A hash mismatch (the file was edited
// after being trusted) returns false -- trust is revoked until re-approved.
func (ts *TrustStore) IsTrusted(o *Overlay) bool {
	if o == nil {
		return false
	}
	h, ok := ts.entries[o.Path]
	return ok && h == o.ContentHash
}

// Trust records (or updates) the overlay's approved content hash.
func (ts *TrustStore) Trust(o *Overlay) {
	ts.entries[o.Path] = o.ContentHash
}

// Untrust removes a path from the trust store. Returns true if it was present.
func (ts *TrustStore) Untrust(path string) bool {
	if _, ok := ts.entries[path]; !ok {
		return false
	}
	delete(ts.entries, path)
	return true
}

// Entries returns the trusted entries sorted by path (for listing / determinism).
func (ts *TrustStore) Entries() []TrustEntry {
	out := make([]TrustEntry, 0, len(ts.entries))
	for p, h := range ts.entries {
		out = append(out, TrustEntry{Path: p, ContentHash: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Save writes the trust store atomically-ish (0600 file, 0700 parent dir). The
// parent is ~/.agentjail, which the shield makes agent-unwritable, so only
// out-of-sandbox `agentjail trust` can mutate it.
func (ts *TrustStore) Save() error {
	if err := os.MkdirAll(filepath.Dir(ts.path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(trustFile{Trusted: ts.Entries()})
	if err != nil {
		return err
	}
	return os.WriteFile(ts.path, data, 0o600)
}
