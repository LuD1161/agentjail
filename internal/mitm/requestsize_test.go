package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A body past the scan window is streamed, not buffered, so its size was only
// ever the window's size. D2 budgets eviction against request_size. AGE-243.
func TestRequestSizeCountsBodyPastScanWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bodyLen int
	}{
		{name: "under the scan window", bodyLen: 4 << 10},
		{name: "one byte over", bodyLen: maxBodyScan + 1},
		{name: "three times over", bodyLen: 3 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamGot int64
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamGot, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			caCert, caKey, err := GenerateCA(t.TempDir())
			if err != nil {
				t.Fatalf("GenerateCA: %v", err)
			}

			var lastLog *RequestLog
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			handler := NewMITMHandler(caCert, caKey, logger, func(rl *RequestLog) { lastLog = rl })
			handler.UpstreamTLSConfig = upstreamTLSConfig(upstream)

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			upstreamAddr := strings.TrimPrefix(upstream.URL, "https://")
			_, port, _ := net.SplitHostPort(upstreamAddr)
			const host = "localhost"

			done := make(chan struct{})
			go func() {
				defer close(done)
				handler.Handle(serverConn, host, port)
			}()

			pool := x509.NewCertPool()
			pool.AddCert(caCert)
			clientTLS := tls.Client(clientConn, &tls.Config{ServerName: host, RootCAs: pool})
			if err := clientTLS.Handshake(); err != nil {
				t.Fatalf("client TLS handshake: %v", err)
			}

			payload := bytes.Repeat([]byte("A"), tc.bodyLen)
			req, _ := http.NewRequest("POST", "https://"+upstreamAddr+"/upload", bytes.NewReader(payload))
			req.ContentLength = int64(tc.bodyLen)

			// net.Pipe is unbuffered: a body larger than the socket buffer would
			// deadlock if written before the response is being read.
			go func() {
				if err := req.Write(clientTLS); err != nil {
					t.Logf("write request: %v", err)
				}
			}()

			resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			clientTLS.Close()
			<-done

			if lastLog == nil {
				t.Fatal("no RequestLog emitted")
			}
			if upstreamGot != int64(tc.bodyLen) {
				t.Fatalf("upstream received %d bytes, want %d: forwarding is broken, "+
					"so the size assertion below would be meaningless",
					upstreamGot, tc.bodyLen)
			}
			if lastLog.RequestSize != int64(tc.bodyLen) {
				t.Errorf("RequestSize = %d, want %d (off by %d)",
					lastLog.RequestSize, tc.bodyLen, int64(tc.bodyLen)-lastLog.RequestSize)
			}
		})
	}
}
