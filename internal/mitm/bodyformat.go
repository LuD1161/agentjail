package mitm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// The AJBODY container: a chunked-AEAD body file whose header splits into an
// immutable half (bound into every chunk's AAD) and a rewritable key envelope.
// See ADR 0095-chunked-body-envelope.
const (
	bodyMagic         = "AJBODY\x00"
	bodyFormatVersion = 1
	bodyChunkSize     = 64 << 10
	bodyEmetaCap      = 512
	bodyAlgAES256GCM  = 1
	bodyTagLen        = 16
	bodyDEKLen        = 32
)

// bodyPlaintextLenUnknown fills plaintext_len when the size is not known at
// header-write time, which for a teed capture is always.
const bodyPlaintextLenUnknown = ^uint64(0)

// Side names which body of a request/response pair a file holds. It is bound
// into the key-wrap AAD, so a wrapped DEK cannot cross sides.
type Side uint8

const (
	SideRequest  Side = 1
	SideResponse Side = 2
)

type bodyEncoding uint8

const (
	bodyEncodingDecoded bodyEncoding = 0
	bodyEncodingRaw     bodyEncoding = 1
)

// imeta is immutable for the file's life: every field is bound into every
// chunk's AAD, so rewriting one would fail authentication on every chunk.
// See ADR 0095-chunked-body-envelope.
type imeta struct {
	dataAlg      uint8
	chunkSize    uint32
	fileID       [16]byte
	side         Side
	sessionID    [16]byte
	encodingRaw  bodyEncoding
	plaintextLen uint64
}

const imetaLen = 1 + 4 + 16 + 1 + 16 + 1 + 8

func (m imeta) marshal() []byte {
	b := make([]byte, 0, imetaLen)
	b = append(b, m.dataAlg)
	b = binary.BigEndian.AppendUint32(b, m.chunkSize)
	b = append(b, m.fileID[:]...)
	b = append(b, uint8(m.side))
	b = append(b, m.sessionID[:]...)
	b = append(b, uint8(m.encodingRaw))
	return binary.BigEndian.AppendUint64(b, m.plaintextLen)
}

func parseIMeta(b []byte) (imeta, error) {
	if len(b) != imetaLen {
		return imeta{}, fmt.Errorf("mitm/bodyformat: imeta is %d bytes, want %d", len(b), imetaLen)
	}
	var m imeta
	m.dataAlg = b[0]
	m.chunkSize = binary.BigEndian.Uint32(b[1:5])
	copy(m.fileID[:], b[5:21])
	m.side = Side(b[21])
	copy(m.sessionID[:], b[22:38])
	m.encodingRaw = bodyEncoding(b[38])
	m.plaintextLen = binary.BigEndian.Uint64(b[39:47])
	if m.dataAlg != bodyAlgAES256GCM {
		return imeta{}, fmt.Errorf("mitm/bodyformat: unknown data alg %d", m.dataAlg)
	}
	if m.chunkSize == 0 || m.chunkSize > 1<<26 {
		return imeta{}, fmt.Errorf("mitm/bodyformat: implausible chunk size %d", m.chunkSize)
	}
	return m, nil
}

// emeta is the key envelope. It is rewritten in place on rotation and is never
// in a chunk's AAD; the key-wrap's own AAD authenticates it.
type emeta struct {
	kekAlg     uint8
	kekID      []byte
	wrappedDEK []byte
}

func (e emeta) marshal() []byte {
	b := make([]byte, 0, 1+2+len(e.kekID)+2+len(e.wrappedDEK))
	b = append(b, e.kekAlg)
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.kekID)))
	b = append(b, e.kekID...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.wrappedDEK)))
	return append(b, e.wrappedDEK...)
}

func parseEMeta(b []byte) (emeta, error) {
	bad := errors.New("mitm/bodyformat: malformed key envelope")
	if len(b) < 5 {
		return emeta{}, bad
	}
	var e emeta
	e.kekAlg = b[0]
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) < 3+n+2 {
		return emeta{}, bad
	}
	e.kekID = b[3 : 3+n]
	rest := b[3+n:]
	w := int(binary.BigEndian.Uint16(rest[0:2]))
	if len(rest) < 2+w {
		return emeta{}, bad
	}
	e.wrappedDEK = rest[2 : 2+w]
	return e, nil
}

// bodyHeaderLen is fixed for v1, which is what keeps chunk 0 at the same offset
// across a rewrap. See ADR 0095-chunked-body-envelope.
const bodyHeaderLen = len(bodyMagic) + 1 + 4 + imetaLen + 4 + 4 + bodyEmetaCap

// emetaLenOff is where emeta_len sits, i.e. where a rewrap starts writing.
const emetaLenOff = len(bodyMagic) + 1 + 4 + imetaLen + 4

// wrapAAD binds a wrapped DEK to one file and side, so it cannot be lifted into
// another file. See ADR 0095-chunked-body-envelope.
func wrapAAD(fileID [16]byte, side Side) []byte {
	a := make([]byte, 0, 10+1+16+1)
	a = append(a, "AJBODYKEK\x00"...)
	a = append(a, bodyFormatVersion)
	a = append(a, fileID[:]...)
	return append(a, uint8(side))
}

// chunkAAD binds a chunk to the immutable header, its index and whether it ends
// the file. emeta is deliberately absent: including it would break rotation.
// See ADR 0095-chunked-body-envelope.
func chunkAAD(im []byte, idx uint64, final bool) []byte {
	a := make([]byte, 0, len(im)+9)
	a = append(a, im...)
	a = binary.BigEndian.AppendUint64(a, idx)
	if final {
		return append(a, 1)
	}
	return append(a, 0)
}

// chunkNonce counts under a per-file DEK, so it cannot collide across files.
func chunkNonce(idx uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], idx)
	return n[:]
}

// sessionKey folds an opaque session id into the fixed 16-byte imeta field.
func sessionKey(session string) [16]byte {
	sum := sha256.Sum256([]byte(session))
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func newFileID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mitm/bodyformat: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// bodyWriter seals plaintext into fixed-size chunks. Peak memory is one chunk,
// which is the ADR 0092 D1 invariant restated for the encrypted path.
type bodyWriter struct {
	f    io.WriteCloser
	aead cipher.AEAD
	im   []byte
	buf  []byte
	out  []byte
	idx  uint64
}

func newBodyWriter(f io.WriteCloser, kw KeyWrapper, m imeta) (*bodyWriter, error) {
	dek := make([]byte, bodyDEKLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("mitm/bodyformat: dek: %w", err)
	}
	kekID, wrapped, err := kw.Wrap(dek, wrapAAD(m.fileID, m.side))
	if err != nil {
		return nil, fmt.Errorf("mitm/bodyformat: wrap dek: %w", err)
	}
	env := emeta{kekAlg: bodyAlgAES256GCM, kekID: []byte(kekID), wrappedDEK: wrapped}.marshal()
	// Growing the slot would move every chunk; that is a format v2, not a relayout.
	if len(env) > bodyEmetaCap {
		return nil, fmt.Errorf("mitm/bodyformat: key envelope is %d bytes, cap is %d: needs format v2",
			len(env), bodyEmetaCap)
	}
	aead, err := gcmFor(dek)
	if err != nil {
		return nil, err
	}

	im := m.marshal()
	hdr := make([]byte, 0, bodyHeaderLen)
	hdr = append(hdr, bodyMagic...)
	hdr = append(hdr, bodyFormatVersion)
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(im)))
	hdr = append(hdr, im...)
	hdr = binary.BigEndian.AppendUint32(hdr, bodyEmetaCap)
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(env)))
	hdr = append(hdr, env...)
	hdr = append(hdr, make([]byte, bodyEmetaCap-len(env))...)
	if _, err := f.Write(hdr); err != nil {
		return nil, fmt.Errorf("mitm/bodyformat: write header: %w", err)
	}
	cs := int(m.chunkSize)
	return &bodyWriter{
		f:    f,
		aead: aead,
		im:   im,
		buf:  make([]byte, 0, cs),
		out:  make([]byte, 0, cs+bodyTagLen),
	}, nil
}

// Write holds a full chunk back until more bytes arrive, so the final chunk is
// only sealed by Close and the final flag is always right.
func (w *bodyWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if len(w.buf) == cap(w.buf) {
			if err := w.flush(false); err != nil {
				return 0, err
			}
		}
		k := cap(w.buf) - len(w.buf)
		if k > len(p) {
			k = len(p)
		}
		w.buf = append(w.buf, p[:k]...)
		p = p[k:]
	}
	return n, nil
}

func (w *bodyWriter) flush(final bool) error {
	ct := w.aead.Seal(w.out[:0], chunkNonce(w.idx), w.buf, chunkAAD(w.im, w.idx, final))
	if _, err := w.f.Write(ct); err != nil {
		return fmt.Errorf("mitm/bodyformat: write chunk %d: %w", w.idx, err)
	}
	w.idx++
	w.buf = w.buf[:0]
	return nil
}

// Close seals the final chunk -- a zero-length body still gets one, or an empty
// file would be indistinguishable from a truncated one.
func (w *bodyWriter) Close() error {
	err := w.flush(true)
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// bodyReader opens chunks in order, one at a time.
type bodyReader struct {
	f    *os.File
	aead cipher.AEAD
	im   []byte
	blk  int64
	rem  int64
	idx  uint64
	buf  []byte
	ct   []byte
	pt   []byte
	done bool
}

func newBodyReader(f *os.File, kw KeyWrapper) (*bodyReader, error) {
	hdr := make([]byte, bodyHeaderLen)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, fmt.Errorf("mitm/bodyformat: read header: %w", err)
	}
	if string(hdr[:len(bodyMagic)]) != bodyMagic {
		return nil, errors.New("mitm/bodyformat: not an AJBODY file")
	}
	p := len(bodyMagic)
	if hdr[p] != bodyFormatVersion {
		return nil, fmt.Errorf("mitm/bodyformat: version %d, want %d", hdr[p], bodyFormatVersion)
	}
	p++
	if n := binary.BigEndian.Uint32(hdr[p : p+4]); int(n) != imetaLen {
		return nil, fmt.Errorf("mitm/bodyformat: imeta_len %d, want %d", n, imetaLen)
	}
	p += 4
	im := hdr[p : p+imetaLen]
	m, err := parseIMeta(im)
	if err != nil {
		return nil, err
	}
	p += imetaLen
	if c := binary.BigEndian.Uint32(hdr[p : p+4]); int(c) != bodyEmetaCap {
		return nil, fmt.Errorf("mitm/bodyformat: emeta_cap %d, want %d", c, bodyEmetaCap)
	}
	p += 4
	el := int(binary.BigEndian.Uint32(hdr[p : p+4]))
	p += 4
	if el > bodyEmetaCap {
		return nil, fmt.Errorf("mitm/bodyformat: emeta_len %d exceeds cap %d", el, bodyEmetaCap)
	}
	env, err := parseEMeta(hdr[p : p+el])
	if err != nil {
		return nil, err
	}
	dek, err := kw.Unwrap(string(env.kekID), env.wrappedDEK, wrapAAD(m.fileID, m.side))
	if err != nil {
		return nil, err
	}
	aead, err := gcmFor(dek)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("mitm/bodyformat: stat: %w", err)
	}
	rem := fi.Size() - int64(bodyHeaderLen)
	if rem < bodyTagLen {
		return nil, fmt.Errorf("mitm/bodyformat: chunk region is %d bytes, truncated", rem)
	}
	blk := int64(m.chunkSize) + bodyTagLen
	return &bodyReader{
		f: f, aead: aead, im: im, blk: blk, rem: rem,
		ct: make([]byte, blk),
		pt: make([]byte, 0, m.chunkSize),
	}, nil
}

func (r *bodyReader) next() error {
	n := r.blk
	final := false
	if r.rem <= r.blk {
		n, final = r.rem, true
	}
	if _, err := io.ReadFull(r.f, r.ct[:n]); err != nil {
		return fmt.Errorf("mitm/bodyformat: read chunk %d: %w", r.idx, err)
	}
	pt, err := r.aead.Open(r.pt[:0], chunkNonce(r.idx), r.ct[:n], chunkAAD(r.im, r.idx, final))
	if err != nil {
		return fmt.Errorf("mitm/bodyformat: chunk %d fails authentication (truncated, reordered or tampered): %w", r.idx, err)
	}
	r.buf = pt
	r.rem -= n
	r.idx++
	r.done = final
	return nil
}

func (r *bodyReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *bodyReader) Close() error { return r.f.Close() }

// rewrapBodyFile rewrites the key envelope in place under kw's current KEK.
// Chunks are untouched and their offsets cannot move.
// See ADR 0095-chunked-body-envelope.
func rewrapBodyFile(path string, kw KeyWrapper) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("mitm/bodyformat: rewrap open: %w", err)
	}
	defer f.Close()

	hdr := make([]byte, bodyHeaderLen)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return fmt.Errorf("mitm/bodyformat: rewrap header: %w", err)
	}
	if string(hdr[:len(bodyMagic)]) != bodyMagic || hdr[len(bodyMagic)] != bodyFormatVersion {
		return errors.New("mitm/bodyformat: rewrap: not a v1 AJBODY file")
	}
	m, err := parseIMeta(hdr[len(bodyMagic)+1+4 : len(bodyMagic)+1+4+imetaLen])
	if err != nil {
		return err
	}
	el := int(binary.BigEndian.Uint32(hdr[emetaLenOff : emetaLenOff+4]))
	if el > bodyEmetaCap {
		return fmt.Errorf("mitm/bodyformat: emeta_len %d exceeds cap %d", el, bodyEmetaCap)
	}
	old, err := parseEMeta(hdr[emetaLenOff+4 : emetaLenOff+4+el])
	if err != nil {
		return err
	}
	aad := wrapAAD(m.fileID, m.side)
	dek, err := kw.Unwrap(string(old.kekID), old.wrappedDEK, aad)
	if err != nil {
		return err
	}
	kekID, wrapped, err := kw.Wrap(dek, aad)
	if err != nil {
		return fmt.Errorf("mitm/bodyformat: rewrap: %w", err)
	}
	env := emeta{kekAlg: bodyAlgAES256GCM, kekID: []byte(kekID), wrappedDEK: wrapped}.marshal()
	if len(env) > bodyEmetaCap {
		return fmt.Errorf("mitm/bodyformat: rewrapped envelope is %d bytes, cap is %d: needs format v2",
			len(env), bodyEmetaCap)
	}
	slot := make([]byte, 4+bodyEmetaCap)
	binary.BigEndian.PutUint32(slot[:4], uint32(len(env)))
	copy(slot[4:], env)
	if _, err := f.WriteAt(slot, int64(emetaLenOff)); err != nil {
		return fmt.Errorf("mitm/bodyformat: rewrap write: %w", err)
	}
	return f.Sync()
}
