package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// plaintextMarker is what the no-plaintext-on-disk scan looks for: it must
// never survive to a file under the body dir.
const plaintextMarker = "AGENTJAIL-PLAINTEXT-CANARY"

func markerBody(n int) []byte {
	return bytes.Repeat([]byte(plaintextMarker+"."), n/(len(plaintextMarker)+1)+1)
}

func storeBody(t *testing.T, b *BodyStore, enc string, data []byte) (string, bool) {
	t.Helper()
	c, err := b.Create(SideResponse, enc)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rel, raw, err := b.Finish(c)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return rel, raw
}

// assertNoPlaintext scans every file under the store for the canary.
func assertNoPlaintext(t *testing.T, b *BodyStore, what string) {
	t.Helper()
	err := filepath.WalkDir(b.Dir(), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(data, []byte(plaintextMarker)) {
			t.Errorf("%s: %s holds the plaintext canary: plaintext reached the disk", what, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", b.Dir(), err)
	}
}

// Every size around the chunk boundary must survive a round trip; the sizes
// are where an off-by-one in the final-chunk rule would show.
// See ADR 0095-chunked-body-envelope.
func TestEncryptedBodyRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, bodyChunkSize - 1, bodyChunkSize, bodyChunkSize + 1, 10 << 20} {
		b := newEncBodyStore(t)
		want := make([]byte, n)
		for i := range want {
			want[i] = byte(i * 7)
		}
		rel, raw := storeBody(t, b, "", want)
		if n == 0 {
			if rel != "" {
				t.Errorf("empty body stored as %q, want no file", rel)
			}
			continue
		}
		if raw {
			t.Errorf("size %d: stored raw, want decoded", n)
		}
		if !strings.HasSuffix(rel, bodyEncFileExt) {
			t.Errorf("size %d: stored as %q, want a %s file", n, rel, bodyEncFileExt)
		}
		if got := readBody(t, b, rel); !bytes.Equal(got, want) {
			t.Errorf("size %d: read back %d bytes, not byte-identical", n, len(got))
		}
	}
}

// A zero-length body still gets a sealed final chunk, so an empty file cannot
// pass as a valid one. Create/Finish drops it, so exercise the writer directly.
func TestEncryptedZeroLengthBodyIsAuthenticated(t *testing.T) {
	b := newEncBodyStore(t)
	rel, sink, err := b.createSink(SideRequest, false)
	if err != nil {
		t.Fatalf("createSink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fi, err := os.Stat(b.path(rel))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != int64(bodyHeaderLen+bodyTagLen) {
		t.Errorf("zero-length body file is %d bytes, want header + one empty sealed chunk (%d)",
			fi.Size(), bodyHeaderLen+bodyTagLen)
	}
	if got := readBody(t, b, rel); len(got) != 0 {
		t.Errorf("read back %d bytes, want 0", len(got))
	}
}

// Chopping the last chunk must error, not return short data: without a final
// marker, truncation is silently a valid file.
// See ADR 0095-chunked-body-envelope.
func TestEncryptedBodyTruncationDetected(t *testing.T) {
	b := newEncBodyStore(t)
	want := bytes.Repeat([]byte("t"), 3*bodyChunkSize)
	rel, _ := storeBody(t, b, "", want)

	fi, err := os.Stat(b.path(rel))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(b.path(rel), fi.Size()-int64(bodyChunkSize+bodyTagLen)); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	rc, err := b.Open(rel)
	if err == nil && rc != nil {
		_, err = io.Copy(io.Discard, rc)
		rc.Close()
	}
	if err == nil {
		t.Fatal("a truncated body read back without error: truncation is silently a valid file")
	}
	t.Logf("truncation rejected: %v", err)
}

// Swapping two chunks must error: chunk_index is in the AAD for this.
// See ADR 0095-chunked-body-envelope.
func TestEncryptedBodyChunkReorderDetected(t *testing.T) {
	b := newEncBodyStore(t)
	want := bytes.Repeat([]byte("r"), 3*bodyChunkSize)
	rel, _ := storeBody(t, b, "", want)

	raw, err := os.ReadFile(b.path(rel))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	blk := bodyChunkSize + bodyTagLen
	c0 := append([]byte(nil), raw[bodyHeaderLen:bodyHeaderLen+blk]...)
	c1 := append([]byte(nil), raw[bodyHeaderLen+blk:bodyHeaderLen+2*blk]...)
	copy(raw[bodyHeaderLen:], c1)
	copy(raw[bodyHeaderLen+blk:], c0)
	if err := os.WriteFile(b.path(rel), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	rc, err := b.Open(rel)
	if err == nil && rc != nil {
		_, err = io.Copy(io.Discard, rc)
		rc.Close()
	}
	if err == nil {
		t.Fatal("reordered chunks read back without error: chunk_index is not bound into the AAD")
	}
	t.Logf("reorder rejected: %v", err)
}

// A wrapped_dek lifted from one file into another must not open: the key-wrap
// AAD binds file_id and side. See ADR 0095-chunked-body-envelope.
func TestWrappedDEKCannotCrossFiles(t *testing.T) {
	b := newEncBodyStore(t)
	relA, _ := storeBody(t, b, "", bytes.Repeat([]byte("A"), 1024))
	relB, _ := storeBody(t, b, "", bytes.Repeat([]byte("B"), 1024))

	a, err := os.ReadFile(b.path(relA))
	if err != nil {
		t.Fatalf("read A: %v", err)
	}
	bb, err := os.ReadFile(b.path(relB))
	if err != nil {
		t.Fatalf("read B: %v", err)
	}
	// Lift A's whole emeta slot (emeta_len + envelope + pad) into B.
	copy(bb[emetaLenOff:emetaLenOff+4+bodyEmetaCap], a[emetaLenOff:emetaLenOff+4+bodyEmetaCap])
	if err := os.WriteFile(b.path(relB), bb, 0o600); err != nil {
		t.Fatalf("write B: %v", err)
	}

	// The UNWRAP must be what fails. A later chunk error would also error out,
	// but it would mean the DEK crossed files and only the data stopped it.
	rc, err := b.Open(relB)
	if err == nil {
		if rc != nil {
			rc.Close()
		}
		t.Fatal("A's wrapped_dek opened file B: the key-wrap AAD does not bind file_id")
	}
	if !strings.Contains(err.Error(), "wrapped dek fails authentication") {
		t.Errorf("file B failed with %v, want the unwrap itself to reject A's envelope", err)
	}
	t.Logf("cross-file wrapped_dek rejected: %v", err)
}

// Rotation rewrites emeta only. If chunk AAD covered emeta, every chunk would
// fail the moment we rotated -- the P0 this test guards.
// See ADR 0095-chunked-body-envelope.
func TestRewrapLeavesEveryChunkVerifiable(t *testing.T) {
	kw, err := NewMemoryKeyWrapper()
	if err != nil {
		t.Fatalf("NewMemoryKeyWrapper: %v", err)
	}
	b := newStore(t, kw)
	want := bytes.Repeat([]byte("rotate me "), 300000) // several chunks
	rel, _ := storeBody(t, b, "", want)

	if err := kw.AddKEK("kek-generation-two"); err != nil {
		t.Fatalf("AddKEK: %v", err)
	}
	if err := rewrapBodyFile(b.path(rel), kw); err != nil {
		t.Fatalf("rewrapBodyFile: %v", err)
	}
	if got := readBody(t, b, rel); !bytes.Equal(got, want) {
		t.Errorf("after rewrap the body read back %d bytes, want the original %d byte-identical",
			len(got), len(want))
	}
}

// A longer kek_id must not move a single chunk: emeta is a fixed-size slot.
// See ADR 0095-chunked-body-envelope.
func TestRewrapDoesNotMoveChunks(t *testing.T) {
	kw, err := NewMemoryKeyWrapper()
	if err != nil {
		t.Fatalf("NewMemoryKeyWrapper: %v", err)
	}
	b := newStore(t, kw)
	rel, _ := storeBody(t, b, "", bytes.Repeat([]byte("x"), 2*bodyChunkSize+7))

	before, err := os.ReadFile(b.path(rel))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := kw.AddKEK(strings.Repeat("much-longer-kek-id-", 8)); err != nil {
		t.Fatalf("AddKEK: %v", err)
	}
	if err := rewrapBodyFile(b.path(rel), kw); err != nil {
		t.Fatalf("rewrapBodyFile: %v", err)
	}
	after, err := os.ReadFile(b.path(rel))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("file went from %d to %d bytes across a rewrap: the emeta slot is not fixed-size",
			len(before), len(after))
	}
	if !bytes.Equal(before[bodyHeaderLen:], after[bodyHeaderLen:]) {
		t.Errorf("the chunk region changed across a rewrap: chunks are not offset-stable")
	}
	if !bytes.Equal(before[:emetaLenOff], after[:emetaLenOff]) {
		t.Errorf("imeta changed across a rewrap: the immutable half must not move")
	}
	if bytes.Equal(before[emetaLenOff:bodyHeaderLen], after[emetaLenOff:bodyHeaderLen]) {
		t.Errorf("the emeta slot is unchanged: the rewrap did nothing")
	}
}

// hugeKEKWrapper returns a kek id no fixed-size slot can hold.
type hugeKEKWrapper struct{ KeyWrapper }

func (hugeKEKWrapper) Wrap(dek, aad []byte) (string, []byte, error) {
	return strings.Repeat("k", bodyEmetaCap), make([]byte, 64), nil
}

// An envelope past the cap is a format v2, never a silent re-lay-out.
// See ADR 0095-chunked-body-envelope.
func TestEnvelopePastCapFailsLoudly(t *testing.T) {
	_, err := newBodyWriter(nopWriteCloser{io.Discard}, hugeKEKWrapper{}, imeta{
		dataAlg: bodyAlgAES256GCM, chunkSize: bodyChunkSize, side: SideRequest,
		plaintextLen: bodyPlaintextLenUnknown,
	})
	if err == nil {
		t.Fatal("an oversized key envelope was accepted: the slot was silently re-laid-out")
	}
	if !strings.Contains(err.Error(), "format v2") {
		t.Errorf("error = %v, want it to name the format bump", err)
	}
	t.Logf("oversized envelope rejected: %v", err)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// failAfterWriter passes bytes through to a real file, then fails like ENOSPC.
type failAfterWriter struct {
	f     *os.File
	left  int
	fired bool
}

var errDiskFull = errors.New("no space left on device")

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		w.fired = true
		return 0, errDiskFull
	}
	if len(p) > w.left {
		p = p[:w.left]
	}
	n, err := w.f.Write(p)
	w.left -= n
	return n, err
}

func (w *failAfterWriter) Close() error { return w.f.Close() }

// A sink that dies mid-body must not leave plaintext behind. This stands in for
// disk-full: the writer sees a short write and an error, exactly as on ENOSPC.
func TestDiskFullMidCaptureLeavesNoPlaintext(t *testing.T) {
	b := newEncBodyStore(t)
	rel, f, err := b.createFile(rawEncFileExt)
	if err != nil {
		t.Fatalf("createFile: %v", err)
	}
	sink := &failAfterWriter{f: f, left: bodyHeaderLen + 3*(bodyChunkSize+bodyTagLen)}
	w, err := newBodyWriter(sink, b.keys, imeta{
		dataAlg: bodyAlgAES256GCM, chunkSize: bodyChunkSize, side: SideResponse,
		sessionID: sessionKey(b.SessionID()), encodingRaw: bodyEncodingRaw,
		plaintextLen: bodyPlaintextLenUnknown,
	})
	if err != nil {
		t.Fatalf("newBodyWriter: %v", err)
	}
	c := &BodyCapture{rel: rel, side: SideResponse, enc: encIdentity, sink: w}
	c.Write(markerBody(10 << 20))
	if _, _, err := b.Finish(c); err == nil {
		t.Error("a capture whose sink ran out of space reported success")
	} else {
		t.Logf("disk-full capture reported: %v", err)
	}
	if !sink.fired {
		t.Fatal("the simulated disk never filled: the test proved nothing")
	}
	assertNoPlaintext(t, b, "disk full mid-capture")
}

// A gzip stream that fails EARLY: nothing decodes, the raw bytes stay.
func TestEarlyDecodeErrorKeepsRawAndNoPlaintext(t *testing.T) {
	b := newEncBodyStore(t)
	bad := append([]byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff}, markerBody(4096)...)
	rel, raw := storeBody(t, b, "gzip", bad)
	if !raw {
		t.Error("a corrupt gzip stream was marked decoded")
	}
	if !strings.HasSuffix(rel, rawEncFileExt) {
		t.Errorf("stored as %q, want a %s file", rel, rawEncFileExt)
	}
	if got := readBody(t, b, rel); !bytes.Equal(got, bad) {
		t.Errorf("read back %d bytes, want the %d raw bytes verbatim", len(got), len(bad))
	}
	assertNoPlaintext(t, b, "early decode error")
}

// A gzip stream that fails LATE -- after inflating many MB. A one-stage
// gzip-to-file pipeline has thrown the raw bytes away by this point, which is
// exactly ADR 0092 D1's contract broken.
// See ADR 0095-chunked-body-envelope.
func TestLateDecodeErrorKeepsRawBytes(t *testing.T) {
	b := newEncBodyStore(t)
	plain := markerBody(12 << 20)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(plain)
	zw.Close()
	// Drop the trailing CRC32+ISIZE: the reader inflates all 12 MB, then errors.
	late := gz.Bytes()[:gz.Len()-8]

	rel, raw := storeBody(t, b, "gzip", late)
	if !raw {
		t.Fatal("a late gzip failure was marked decoded: the decoded copy is incomplete")
	}
	if !strings.HasSuffix(rel, rawEncFileExt) {
		t.Errorf("stored as %q, want the %s raw fallback", rel, rawEncFileExt)
	}
	if got := readBody(t, b, rel); !bytes.Equal(got, late) {
		t.Errorf("read back %d bytes, want the %d raw compressed bytes: D1's raw fallback was lost",
			len(got), len(late))
	}
	entries, _ := os.ReadDir(filepath.Join(b.Dir(), b.SessionID()))
	if len(entries) != 1 {
		t.Errorf("%d files after a late decode failure, want only the raw fallback", len(entries))
	}
	assertNoPlaintext(t, b, "late decode error")
}

// A gzip bomb aborts and leaves the raw bytes, with no plaintext on disk.
func TestBombAbortLeavesNoPlaintext(t *testing.T) {
	b := newEncBodyStore(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(markerBody(maxExpansionFloor + (1 << 20)))
	zw.Close()

	rel, raw := storeBody(t, b, "gzip", gz.Bytes())
	if !raw {
		t.Error("a bomb-ratio body was decoded, want the raw fallback")
	}
	if got := readBody(t, b, rel); !bytes.Equal(got, gz.Bytes()) {
		t.Errorf("read back %d bytes, want the %d raw compressed bytes", len(got), gz.Len())
	}
	assertNoPlaintext(t, b, "bomb abort")
}

// The happy path: a gzip body decodes, and neither the decoded copy nor the
// discarded stage-1 file holds a plaintext byte.
func TestSuccessfulDecodeLeavesNoPlaintext(t *testing.T) {
	b := newEncBodyStore(t)
	plain := markerBody(2 << 20)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(plain)
	zw.Close()

	rel, raw := storeBody(t, b, "gzip", gz.Bytes())
	if raw {
		t.Fatal("a valid gzip stream did not decode")
	}
	assertNoPlaintext(t, b, "successful decode")
	if !strings.HasSuffix(rel, bodyEncFileExt) {
		t.Errorf("stored as %q, want a %s file", rel, bodyEncFileExt)
	}
	entries, _ := os.ReadDir(filepath.Join(b.Dir(), b.SessionID()))
	if len(entries) != 1 {
		t.Errorf("%d files after a successful decode, want only the decoded copy", len(entries))
	}
	if got := readBody(t, b, rel); !bytes.Equal(got, plain) {
		t.Errorf("read back %d bytes, want the %d decoded bytes", len(got), len(plain))
	}
}

// ADR 0092 D1's memory invariant, re-run with encryption on. A whole-file GCM
// Open on either the write or the read side fails this.
// See ADR 0095-chunked-body-envelope.
func TestEncryptedCapturePeakMemoryDoesNotScaleWithBodySize(t *testing.T) {
	const bodyLen = 128 << 20

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "134217728")
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for sent := 0; sent < bodyLen; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	bodies := newEncBodyStore(t)
	tn := newTunnel(t, upstream, bodies)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	req, _ := http.NewRequest("GET", "https://localhost/big", nil)
	go req.Write(tn.client)
	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("drain body: %v", err)
	}
	resp.Body.Close()
	if n != bodyLen {
		t.Fatalf("client got %d bytes, want %d", n, bodyLen)
	}

	rl := tn.waitLog(t)
	// GC before the second reading too, or the delta counts garbage the
	// collector has not run for yet -- which made this flake under load.
	runtime.GC()
	runtime.ReadMemStats(&after)

	const budget = 8 << 20
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > budget {
		t.Errorf("heap grew %d bytes capturing a %d byte encrypted body (budget %d): the sink is buffering",
			grew, bodyLen, budget)
	}
	if !strings.HasSuffix(rl.ResponseBodyPath, bodyEncFileExt) {
		t.Fatalf("stored path %q is not an encrypted body", rl.ResponseBodyPath)
	}

	// Reading it back must stay flat too: that is what a whole-file Open breaks.
	runtime.GC()
	runtime.ReadMemStats(&before)
	rc, err := bodies.Open(rl.ResponseBodyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.Copy(io.Discard, rc)
	rc.Close()
	if err != nil {
		t.Fatalf("stream body back: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if got != bodyLen {
		t.Errorf("streamed back %d bytes, want %d", got, bodyLen)
	}
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > budget {
		t.Errorf("heap grew %d bytes reading a %d byte encrypted body (budget %d): a whole-file Open",
			grew, bodyLen, budget)
	}
}

// The path guard is the same widened guard for encrypted names.
// See ADR 0092-persist-request-bodies (D1).
func TestEncryptedBodyPathGuard(t *testing.T) {
	b := newEncBodyStore(t)
	for _, rel := range []string{
		"../../etc/passwd.body.enc",
		b.SessionID() + "/../x.raw.enc",
		b.SessionID() + "/x.enc",
		b.SessionID() + "/deadbeef.tar.gz",
	} {
		if rc, err := b.Open(rel); err == nil {
			t.Errorf("Open(%q) was accepted, want rejected", rel)
			if rc != nil {
				rc.Close()
			}
		}
	}
}
