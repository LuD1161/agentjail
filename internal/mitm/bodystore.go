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

// DefaultBodyDir returns the default body directory: ~/.agentjail/bodies.
func DefaultBodyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "agentjail-"+BodyDirName)
	}
	return filepath.Join(home, ".agentjail", BodyDirName)
}

// BodyStore holds captured request/response bodies as files. Paths recorded on
// a row are relative to this directory.
type BodyStore struct {
	dir string
}

// NewBodyStore creates (or opens) the body directory with 0700 permissions.
func NewBodyStore(dir string) (*BodyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mitm/bodystore: mkdir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mitm/bodystore: chmod %s: %w", dir, err)
	}
	return &BodyStore{dir: dir}, nil
}

// Dir returns the body directory.
func (b *BodyStore) Dir() string { return b.dir }

// Open returns a reader for a stored body. A missing file is absent, not an
// error: (nil, nil). See ADR 0092-persist-request-bodies (D1).
func (b *BodyStore) Open(rel string) (io.ReadCloser, error) {
	if b == nil || rel == "" {
		return nil, nil
	}
	// A path recorded by a corrupted row must not reach outside the directory.
	if rel != filepath.Base(rel) || strings.HasPrefix(rel, ".") {
		return nil, fmt.Errorf("mitm/bodystore: bad body path %q", rel)
	}
	f, err := os.Open(filepath.Join(b.dir, rel))
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

func (b *BodyStore) createFile() (string, *os.File, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", nil, fmt.Errorf("mitm/bodystore: name: %w", err)
	}
	rel := hex.EncodeToString(buf[:]) + ".body"
	f, err := os.OpenFile(filepath.Join(b.dir, rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
		_ = os.Remove(filepath.Join(b.dir, c.rel))
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
		_ = os.Remove(filepath.Join(b.dir, c.rel))
		return decoded, false, closeErr
	default:
		return c.rel, true, closeErr
	}
}

// decodeGzip streams rel through gzip into a new file, so peak memory stays at
// the copy buffer. Any failure leaves rel untouched for the raw fallback.
func (b *BodyStore) decodeGzip(rel string) (string, error) {
	src, err := os.Open(filepath.Join(b.dir, rel))
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
		_ = os.Remove(filepath.Join(b.dir, outRel))
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
		_ = os.Remove(filepath.Join(b.dir, outRel))
		return "", err
	}
	return outRel, nil
}
