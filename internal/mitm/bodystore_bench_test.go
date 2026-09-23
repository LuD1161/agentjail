package mitm

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Isolates synchronous capture finalization from initial writes and compression.
func BenchmarkBodyCaptureFinish(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20} {
		for _, encoding := range []string{"", "gzip"} {
			b.Run(fmt.Sprintf("bytes=%d/encoding=%s", size, encoding), func(b *testing.B) {
				raw := bytes.Repeat([]byte("a"), size)
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
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
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
					if err = os.Remove(filepath.Join(store.Dir(), rel)); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
			})
		}
	}
}
