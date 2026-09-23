package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/netpolicy"
	"golang.org/x/net/http2"
)

func TestConfiguredHTTPPolicyVerdicts(t *testing.T) {
	for _, proto := range []string{"http/1.1", "h2"} {
		for _, verdict := range []string{"allow", "deny", "ask"} {
			for _, mode := range []agentconfig.EnforcementMode{agentconfig.EnforcementMonitor, agentconfig.EnforcementEnforce} {
				t.Run(proto+"/"+verdict+"/"+string(mode), func(t *testing.T) {
					var reached atomic.Int32
					upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						reached.Add(1)
						_, _ = w.Write([]byte("upstream response"))
					}))
					logs := make(chan RequestLog, 2)
					h, ca := newTestHandler(t, upstream, func(row *RequestLog) { logs <- *row })
					dir := t.TempDir()
					if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte("id: monitor-test\naction: "+verdict+"\nreason: test verdict\n"), 0600); err != nil {
						t.Fatal(err)
					}
					var err error
					h.Matcher, err = netpolicy.NewMatcherForMode(mode, dir)
					if err != nil {
						t.Fatal(err)
					}
					host, port := upstreamHostPort(t, upstream)
					client, server := net.Pipe()
					defer client.Close()
					defer server.Close()
					_ = client.SetDeadline(time.Now().Add(10 * time.Second))
					go h.Handle(server, host, port)
					roots := x509.NewCertPool()
					roots.AddCert(ca)
					tlsClient := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: host, NextProtos: []string{proto}, MinVersion: tls.VersionTLS12})
					defer tlsClient.Close()
					if err := tlsClient.Handshake(); err != nil {
						t.Fatal(err)
					}
					req, err := http.NewRequest(http.MethodGet, "https://"+net.JoinHostPort(host, port)+"/test", nil)
					if err != nil {
						t.Fatal(err)
					}
					var resp *http.Response
					if proto == "h2" {
						cc, err := (&http2.Transport{}).NewClientConn(tlsClient)
						if err != nil {
							t.Fatal(err)
						}
						defer cc.Close()
						resp, err = cc.RoundTrip(req)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						if err := req.Write(tlsClient); err != nil {
							t.Fatal(err)
						}
						resp, err = http.ReadResponse(bufio.NewReader(tlsClient), req)
						if err != nil {
							t.Fatal(err)
						}
					}
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					wantStatus, wantCalls := http.StatusOK, int32(1)
					wantAction, wantWould := "allow", verdict
					if verdict == "allow" {
						wantWould = ""
					}
					if mode == agentconfig.EnforcementEnforce {
						wantAction, wantWould = verdict, ""
						if verdict != "allow" {
							wantStatus, wantCalls = http.StatusForbidden, 0
						}
					}
					if resp.StatusCode != wantStatus || reached.Load() != wantCalls || (wantCalls == 1 && string(body) != "upstream response") {
						t.Fatalf("status=%d body=%q upstream calls=%d", resp.StatusCode, body, reached.Load())
					}
					select {
					case row := <-logs:
						if row.PolicyAction != wantAction || row.WouldAction != wantWould || row.PolicyTemplate != "monitor-test" || row.StatusCode != wantStatus {
							t.Fatalf("record = %+v", row)
						}
					case <-time.After(10 * time.Second):
						t.Fatal("missing decision log")
					}
				})
			}
		}
	}
}
