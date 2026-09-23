package mitm

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// Isolates synchronous capture finalization from initial writes and compression.
func BenchmarkBodyCaptureFinish(b *testing.B) {
	fixtures := []struct {
		name string
		body func(int) []byte
	}{
		{"repeated", func(size int) []byte { return bytes.Repeat([]byte("a"), size) }},
		{"synthetic-jsonl", syntheticCaptureBody},
	}
	for _, fixture := range fixtures {
		for _, size := range []int{1 << 20, 16 << 20, 64 << 20} {
			for _, encoding := range []string{"identity", "gzip"} {
				b.Run(fmt.Sprintf("fixture=%s/bytes=%d/encoding=%s", fixture.name, size, encoding), func(b *testing.B) {
					raw := fixture.body(size)
					expected := sha256.Sum256(raw)
					wire := raw
					if encoding == "gzip" {
						var compressed bytes.Buffer
						gz := gzip.NewWriter(&compressed)
						if _, err := gz.Write(raw); err != nil {
							b.Fatal(err)
						}
						if err := gz.Close(); err != nil {
							b.Fatal(err)
						}
						wire = compressed.Bytes()
					}
					keys, err := NewMemoryKeyWrapper()
					if err != nil {
						b.Fatal(err)
					}
					store, err := NewBodyStore(b.TempDir(), "measure", keys)
					if err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					b.StopTimer()
					for i := 0; i < b.N; i++ {
						capture, err := store.Create(SideResponse, encoding)
						if err != nil {
							b.Fatal(err)
						}
						if _, err = capture.Write(wire); err != nil {
							b.Fatal(err)
						}
						b.StartTimer()
						rel, isRaw, err := store.Finish(capture)
						b.StopTimer()
						if err != nil || isRaw {
							b.Fatalf("finish: raw=%v err=%v", isRaw, err)
						}
						verifyCapturedBenchmarkBody(b, store, rel, int64(size), expected)
						if err = os.Remove(filepath.Join(store.Dir(), rel)); err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(float64(len(wire)), "wire-bytes/op")
					b.ReportMetric(float64(size)/float64(len(wire)), "expanded/wire")
				})
			}
		}
	}
}

// Deterministic synthetic JSONL mixes repeated prose with changing record fields.
func syntheticCaptureBody(size int) []byte {
	rng := rand.New(rand.NewSource(1))
	paths := []string{"src/client.go", "src/cache.go", "test/request_test.go", "docs/design.md"}
	messages := []string{
		"Read the current source and identify the next validation step.",
		"The response contains the expected fields and a synthetic request ID.",
		"Compare the returned result with the cached metadata for this session.",
		"The operation completed; record timing and continue with the next file.",
	}
	body := make([]byte, 0, size)
	for record := 0; ; record++ {
		line := fmt.Appendf(nil, `{"sequence":%d,"file":%q,"message":%q,"request_id":"%016x%016x","input_tokens":%d,"output_tokens":%d,"elapsed_us":%d}`+"\n",
			record, paths[rng.Intn(len(paths))], messages[rng.Intn(len(messages))],
			rng.Uint64(), rng.Uint64(), 100+rng.Intn(50000), 1+rng.Intn(4000), 100+rng.Intn(100000))
		if len(body)+len(line) > size {
			break
		}
		body = append(body, line...)
	}
	for len(body) < size {
		body = append(body, ' ')
	}
	return body
}

func verifyCapturedBenchmarkBody(b *testing.B, store *BodyStore, rel string, size int64, expected [sha256.Size]byte) {
	b.Helper()
	reader, err := store.Open(rel)
	if err != nil {
		b.Fatal(err)
	}
	if reader == nil {
		b.Fatal("finished capture is missing")
	}
	digest := sha256.New()
	n, readErr := io.Copy(digest, reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		b.Fatalf("read finished capture: read=%v close=%v", readErr, closeErr)
	}
	if n != size || !bytes.Equal(digest.Sum(nil), expected[:]) {
		b.Fatalf("finished capture differs: bytes=%d want=%d", n, size)
	}
}
