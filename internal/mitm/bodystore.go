package mitm

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BodyDirName is the body directory's name inside ~/.agentjail. Exported so the
// shield derives its deny rule from here rather than keeping a second copy.
// See ADR 0092-persist-request-bodies (D3).
const BodyDirName = "bodies"

// captureBufSize bounds the memory one capture holds: peak memory must not
// track body size, which is why bodies are files at all.
// See ADR 0092-persist-request-bodies (D1).
const captureBufSize = 32 << 10

// Decoding is abandoned past maxExpansionRatio, but never below
// maxExpansionFloor: small bodies compress arbitrarily well and are not bombs.
// See ADR 0092-persist-request-bodies (D1).
const (
	maxExpansionRatio = 100
	maxExpansionFloor = 64 << 20
)

// EncodingRawSides marks which captured bodies of a row hold raw encoded bytes
// because decoding failed or was refused.
// See ADR 0092-persist-request-bodies (D1).
type EncodingRawSides string

const (
	EncodingRawNone     EncodingRawSides = ""
	EncodingRawRequest  EncodingRawSides = "request"
	EncodingRawResponse EncodingRawSides = "response"
	EncodingRawBoth     EncodingRawSides = "both"
)

// encodingRawSides combines the per-side raw markers into the row's marker.
func encodingRawSides(reqRaw, respRaw bool) EncodingRawSides {
	switch {
	case reqRaw && respRaw:
		return EncodingRawBoth
	case reqRaw:
		return EncodingRawRequest
	case respRaw:
		return EncodingRawResponse
	default:
		return EncodingRawNone
	}
}

// bodyFileExt is the suffix every stored body path carries.
const bodyFileExt = ".body"

// DefaultBodyDir returns the default body directory: ~/.agentjail/bodies.
// The session dir goes UNDER it: ~/.agentjail/bodies/<session>, because the
// shield's deny covers this name only. See ADR 0092-persist-request-bodies (D3).
func DefaultBodyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "agentjail-"+BodyDirName)
	}
	return filepath.Join(home, ".agentjail", BodyDirName)
}

// NewSessionID mints an opaque id for one shield launch. The shield runs before
// any hook fires and has no agent session id of its own (see netproxy.go).
func NewSessionID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("mitm/bodystore: session id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// validIDComponent reports whether s is an opaque id (hex or ULID) safe as one
// path component: no dot, no separator, so "..", "." and absolute paths cannot
// spell one. See ADR 0092-persist-request-bodies (D1).
func validIDComponent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		default:
			return false
		}
	}
	return true
}

// BodyStore holds captured request/response bodies as files, grouped per
// session: paths recorded on a row are "<session_id>/<body_id>.body", relative
// to the store's root directory.
type BodyStore struct {
	dir     string // root, e.g. ~/.agentjail/bodies
	session string // this launch's group; captures land in dir/session
}

// NewBodyStore creates (or opens) the root and this session's directory, both
// 0700.
func NewBodyStore(dir, sessionID string) (*BodyStore, error) {
	if !validIDComponent(sessionID) {
		return nil, fmt.Errorf("mitm/bodystore: bad session id %q", sessionID)
	}
	for _, d := range []string{dir, filepath.Join(dir, sessionID)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("mitm/bodystore: mkdir %s: %w", d, err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, fmt.Errorf("mitm/bodystore: chmod %s: %w", d, err)
		}
	}
	return &BodyStore{dir: dir, session: sessionID}, nil
}

// Dir returns the store's root directory, not this session's subdirectory.
func (b *BodyStore) Dir() string { return b.dir }

// SessionID returns the session every capture of this store groups under.
func (b *BodyStore) SessionID() string { return b.session }

// resolve turns a stored relative path into an absolute one, or rejects it.
// network.db is writable by any same-uid process, so a stored path is untrusted
// input. See ADR 0092-persist-request-bodies (D1).
func (b *BodyStore) resolve(rel string) (string, error) {
	comps := strings.Split(rel, "/")
	if len(comps) != 2 || !validIDComponent(comps[0]) {
		return "", fmt.Errorf("mitm/bodystore: bad body path %q", rel)
	}
	base, ok := strings.CutSuffix(comps[1], bodyFileExt)
	if !ok || !validIDComponent(base) {
		return "", fmt.Errorf("mitm/bodystore: bad body path %q", rel)
	}
	// A symlink at any component would re-point a read outside the store.
	p := b.dir
	for _, c := range comps {
		p = filepath.Join(p, c)
		fi, err := os.Lstat(p)
		if os.IsNotExist(err) {
			break // absent, not an escape: the caller's open reports it
		}
		if err != nil {
			return "", fmt.Errorf("mitm/bodystore: stat %s: %w", rel, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("mitm/bodystore: symlinked body path %q", rel)
		}
	}
	return filepath.Join(b.dir, comps[0], comps[1]), nil
}

// Open returns a reader for a stored body. A missing file is absent, not an
// error: (nil, nil). See ADR 0092-persist-request-bodies (D1).
func (b *BodyStore) Open(rel string) (io.ReadCloser, error) {
	if b == nil || rel == "" {
		return nil, nil
	}
	full, err := b.resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mitm/bodystore: open %s: %w", rel, err)
	}
	return f, nil
}

// bodyCapture streams a body to a file and counts every byte that passes.
// Write never fails the caller: it is teed off a live proxy hop, and a
// recording failure must not break the request.
// See ADR 0092-persist-request-bodies (D1).
type bodyCapture struct {
	rel   string
	f     *os.File
	w     *bufio.Writer
	total int64
	err   error
}

// Create opens a capture. The name is generated before any byte is written:
// the body streams to disk before the INSERT that would assign a row id.
// See ADR 0092-persist-request-bodies (D1).
func (b *BodyStore) Create() (*bodyCapture, error) {
	if b == nil {
		return nil, nil
	}
	rel, f, err := b.createFile()
	if err != nil {
		return nil, err
	}
	return &bodyCapture{rel: rel, f: f, w: bufio.NewWriterSize(f, captureBufSize)}, nil
}

// path maps a stored relative path to this store's filesystem path. Stored
// paths always use "/", whatever the OS separator is.
func (b *BodyStore) path(rel string) string {
	return filepath.Join(b.dir, filepath.FromSlash(rel))
}

func (b *BodyStore) createFile() (string, *os.File, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", nil, fmt.Errorf("mitm/bodystore: name: %w", err)
	}
	rel := b.session + "/" + hex.EncodeToString(buf[:]) + bodyFileExt
	f, err := os.OpenFile(b.path(rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("mitm/bodystore: create %s: %w", rel, err)
	}
	return rel, f, nil
}

func (c *bodyCapture) Write(p []byte) (int, error) {
	if c == nil {
		return len(p), nil
	}
	c.total += int64(len(p))
	if c.err == nil {
		if _, err := c.w.Write(p); err != nil {
			c.err = err
		}
	}
	return len(p), nil
}

// Size returns the bytes that passed through the capture, whether or not they
// reached the disk.
func (c *bodyCapture) Size() int64 {
	if c == nil {
		return 0
	}
	return c.total
}

func (c *bodyCapture) close() error {
	if err := c.w.Flush(); err != nil && c.err == nil {
		c.err = err
	}
	if err := c.f.Close(); err != nil && c.err == nil {
		c.err = err
	}
	return c.err
}

// Finish closes the capture and normalizes it against contentEncoding,
// returning the stored path and whether the file holds raw encoded bytes.
// Decoding is best-effort; the bytes are not.
// See ADR 0092-persist-request-bodies (D1).
func (b *BodyStore) Finish(c *bodyCapture, contentEncoding string) (rel string, raw bool, err error) {
	if b == nil || c == nil {
		return "", false, nil
	}
	closeErr := c.close()
	if c.total == 0 {
		_ = os.Remove(b.path(c.rel))
		return "", false, closeErr
	}
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "", "identity":
		return c.rel, false, closeErr
	case "gzip", "x-gzip":
		decoded, derr := b.decodeGzip(c.rel)
		if derr != nil {
			return c.rel, true, closeErr
		}
		_ = os.Remove(b.path(c.rel))
		return decoded, false, closeErr
	default:
		return c.rel, true, closeErr
	}
}

// decodeGzip streams rel through gzip into a new file, so peak memory stays at
// the copy buffer. Any failure leaves rel untouched for the raw fallback.
func (b *BodyStore) decodeGzip(rel string) (string, error) {
	src, err := os.Open(b.path(rel))
	if err != nil {
		return "", err
	}
	defer src.Close()

	gr, err := gzip.NewReader(src)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	outRel, out, err := b.createFile()
	if err != nil {
		return "", err
	}
	cerr := func(e error) (string, error) {
		out.Close()
		_ = os.Remove(b.path(outRel))
		return "", e
	}

	in, err := src.Stat()
	if err != nil {
		return cerr(err)
	}
	limit := in.Size() * maxExpansionRatio
	if limit < maxExpansionFloor {
		limit = maxExpansionFloor
	}
	n, err := io.Copy(out, io.LimitReader(gr, limit+1))
	if err != nil {
		return cerr(err)
	}
	if n > limit {
		return cerr(fmt.Errorf("mitm/bodystore: %s expands past %d bytes", rel, limit))
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(b.path(outRel))
		return "", err
	}
	return outRel, nil
}
