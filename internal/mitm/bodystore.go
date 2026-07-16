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

// The suffixes a stored body path may carry: a plaintext body, stage 1's
// encrypted wire bytes, or stage 2's encrypted decoded copy.
// See ADR 0095-chunked-body-envelope.
const (
	bodyFileExt    = ".body"
	rawEncFileExt  = ".raw.enc"
	bodyEncFileExt = ".body.enc"
)

var bodyFileExts = []string{bodyEncFileExt, rawEncFileExt, bodyFileExt}

// contentEnc is what Content-Encoding means for the capture: store as-is,
// attempt a gunzip pass, or keep raw because we cannot decode it.
type contentEnc uint8

const (
	encIdentity contentEnc = iota
	encGzip
	encUnsupported
)

func normalizeEncoding(s string) contentEnc {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "identity":
		return encIdentity
	case "gzip", "x-gzip":
		return encGzip
	default:
		return encUnsupported
	}
}

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

// validBodyFileName reports whether name is exactly <id> plus one known
// suffix, so no other file under the store can be named by a stored path.
func validBodyFileName(name string) bool {
	for _, ext := range bodyFileExts {
		if base, ok := strings.CutSuffix(name, ext); ok {
			return validIDComponent(base)
		}
	}
	return false
}

// BodyStore holds captured request/response bodies as files, grouped per
// session: paths recorded on a row are "<session_id>/<body_id>.body", relative
// to the store's root directory.
type BodyStore struct {
	dir     string // root, e.g. ~/.agentjail/bodies
	session string // this launch's group; captures land in dir/session
	keys    KeyWrapper
}

// NewBodyStore creates (or opens) the root and this session's directory, both
// 0700. A nil keys stores bodies in the clear; supply one and every byte at
// rest is chunked AEAD. See ADR 0095-chunked-body-envelope.
func NewBodyStore(dir, sessionID string, keys KeyWrapper) (*BodyStore, error) {
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
	return &BodyStore{dir: dir, session: sessionID, keys: keys}, nil
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
	if !validBodyFileName(comps[1]) {
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

// Open returns a reader for a stored body, decrypting as it streams. A missing
// file is absent, not an error: (nil, nil).
// See ADR 0092-persist-request-bodies (D1).
func (b *BodyStore) Open(rel string) (io.ReadCloser, error) {
	if b == nil || rel == "" {
		return nil, nil
	}
	if _, err := b.resolve(rel); err != nil {
		return nil, err
	}
	rc, err := b.openStored(rel)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return rc, err
}

func (b *BodyStore) openStored(rel string) (io.ReadCloser, error) {
	f, err := os.Open(b.path(rel))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("mitm/bodystore: open %s: %w", rel, err)
	}
	if b.keys == nil {
		return f, nil
	}
	r, err := newBodyReader(f, b.keys)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mitm/bodystore: open %s: %w", rel, err)
	}
	return r, nil
}

// captureSink is what a capture writes into: a buffered plaintext file, or a
// chunked-AEAD writer. Close finalizes and closes the underlying file.
type captureSink interface {
	io.Writer
	Close() error
}

// plainSink is the unencrypted sink, kept for a store with no KeyWrapper.
type plainSink struct {
	f *os.File
	w *bufio.Writer
}

func (s *plainSink) Write(p []byte) (int, error) { return s.w.Write(p) }

func (s *plainSink) Close() error {
	err := s.w.Flush()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// bodyCapture streams a body to a file and counts every byte that passes.
// Write never fails the caller: it is teed off a live proxy hop, and a
// recording failure must not break the request.
// See ADR 0092-persist-request-bodies (D1).
type bodyCapture struct {
	rel   string
	side  Side
	enc   contentEnc
	sink  captureSink
	total int64
	err   error
}

// Create opens a capture. The name is generated before any byte is written:
// the body streams to disk before the INSERT that would assign a row id.
// contentEncoding is taken now because it picks the sink's stage-1 identity.
// See ADR 0092-persist-request-bodies (D1), ADR 0095-chunked-body-envelope.
func (b *BodyStore) Create(side Side, contentEncoding string) (*bodyCapture, error) {
	if b == nil {
		return nil, nil
	}
	enc := normalizeEncoding(contentEncoding)
	// Wire bytes are the plaintext body only when nothing encoded them.
	rel, sink, err := b.createSink(side, enc != encIdentity)
	if err != nil {
		return nil, err
	}
	return &bodyCapture{rel: rel, side: side, enc: enc, sink: sink}, nil
}

// path maps a stored relative path to this store's filesystem path. Stored
// paths always use "/", whatever the OS separator is.
func (b *BodyStore) path(rel string) string {
	return filepath.Join(b.dir, filepath.FromSlash(rel))
}

// createSink opens a new body file. raw says the bytes about to be written are
// still encoded, which names the file and fills imeta's encoding_raw.
func (b *BodyStore) createSink(side Side, raw bool) (string, captureSink, error) {
	ext := bodyFileExt
	if b.keys != nil {
		ext = bodyEncFileExt
		if raw {
			ext = rawEncFileExt
		}
	}
	rel, f, err := b.createFile(ext)
	if err != nil {
		return "", nil, err
	}
	if b.keys == nil {
		return rel, &plainSink{f: f, w: bufio.NewWriterSize(f, captureBufSize)}, nil
	}
	fileID, err := newFileID()
	if err != nil {
		f.Close()
		_ = os.Remove(b.path(rel))
		return "", nil, fmt.Errorf("mitm/bodystore: file id: %w", err)
	}
	encoding := bodyEncodingDecoded
	if raw {
		encoding = bodyEncodingRaw
	}
	w, err := newBodyWriter(f, b.keys, imeta{
		dataAlg:      bodyAlgAES256GCM,
		chunkSize:    bodyChunkSize,
		fileID:       fileID,
		side:         side,
		sessionID:    sessionKey(b.session),
		encodingRaw:  encoding,
		plaintextLen: bodyPlaintextLenUnknown,
	})
	if err != nil {
		f.Close()
		_ = os.Remove(b.path(rel))
		return "", nil, fmt.Errorf("mitm/bodystore: create %s: %w", rel, err)
	}
	return rel, w, nil
}

func (b *BodyStore) createFile(ext string) (string, *os.File, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", nil, fmt.Errorf("mitm/bodystore: name: %w", err)
	}
	rel := b.session + "/" + hex.EncodeToString(buf[:]) + ext
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
		if _, err := c.sink.Write(p); err != nil {
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
	if err := c.sink.Close(); err != nil && c.err == nil {
		c.err = err
	}
	return c.err
}

// Finish closes stage 1 and runs stage 2 if the bytes are gzip, returning the
// stored path and whether the file holds raw encoded bytes. A decode failure
// keeps stage 1's file: decoding is best-effort, the bytes are not.
// See ADR 0092-persist-request-bodies (D1), ADR 0095-chunked-body-envelope.
func (b *BodyStore) Finish(c *bodyCapture) (rel string, raw bool, err error) {
	if b == nil || c == nil {
		return "", false, nil
	}
	closeErr := c.close()
	if c.total == 0 {
		_ = os.Remove(b.path(c.rel))
		return "", false, closeErr
	}
	if c.enc != encGzip {
		return c.rel, c.enc != encIdentity, closeErr
	}
	decoded, derr := b.decodeGzip(c)
	if derr != nil {
		return c.rel, true, closeErr
	}
	_ = os.Remove(b.path(c.rel))
	return decoded, false, closeErr
}

// decodeGzip is stage 2: read stage 1's file back, inflate and re-seal, one
// chunk at a time, so peak memory stays bounded and no plaintext byte is ever
// written. Any failure leaves stage 1's file for the raw fallback.
// See ADR 0095-chunked-body-envelope.
func (b *BodyStore) decodeGzip(c *bodyCapture) (string, error) {
	src, err := b.openStored(c.rel)
	if err != nil {
		return "", err
	}
	defer src.Close()

	gr, err := gzip.NewReader(src)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	outRel, out, err := b.createSink(c.side, false)
	if err != nil {
		return "", err
	}
	cerr := func(e error) (string, error) {
		out.Close()
		_ = os.Remove(b.path(outRel))
		return "", e
	}

	limit := c.total * maxExpansionRatio
	if limit < maxExpansionFloor {
		limit = maxExpansionFloor
	}
	n, err := io.CopyBuffer(out, io.LimitReader(gr, limit+1), make([]byte, bodyChunkSize))
	if err != nil {
		return cerr(err)
	}
	if n > limit {
		return cerr(fmt.Errorf("mitm/bodystore: %s expands past %d bytes", c.rel, limit))
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(b.path(outRel))
		return "", err
	}
	return outRel, nil
}
