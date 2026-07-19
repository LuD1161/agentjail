//go:build linux

// Self-reexec h2/gRPC test client (R3.2-R3.4, AGE-223 tunnel e2e).
//
// The TUN created by netns.CreateWithTUN lives inside a fresh network
// namespace; only a process that has joined that namespace (via
// ns.ExecIn/nsenter) can route to the VIP. bash's /dev/tcp (used by the plain
// TCP e2e test) cannot do a TLS+ALPN handshake, so h2/gRPC traffic needs a
// real Go TLS client running INSIDE the namespace.
//
// Rather than shell out to curl/openssl (which cannot reliably report h2
// trailers), this test binary re-execs itself as that client: ns.ExecIn runs
// os.Args[0] (this compiled test binary) with a sentinel first argument
// inside the netns. h2HelperMain intercepts that sentinel in TestMain, before
// netns.MaybeRunReexec and before go test's own flag parsing, runs the
// client, and os.Exit()s -- mirroring the TUN-holder reexec pattern in
// netns.MaybeRunReexec (tunsetup_linux.go).
package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
)

// h2HelperArg is the sentinel os.Args[1] that routes this test binary into
// h2HelperMain instead of the normal go test entrypoint. Must not collide
// with netns's own reexec markers (reexecTUNArg / reexecHardenArg), which are
// unexported in package netns -- an unrelated string avoids any chance of a
// collision.
const h2HelperArg = "agentjail-h2e2e-client-helper"

// h2HelperALPN selects what the client offers/accepts during the TLS
// handshake, exercising the R3.4 ALPN edge cases.
type h2HelperALPN string

const (
	alpnH2Only h2HelperALPN = "h2only" // client offers ONLY "h2"; no h1 fallback
	alpnH1Only h2HelperALPN = "h1only" // client offers ONLY "http/1.1"; never speaks h2
	alpnBoth   h2HelperALPN = "both"   // client offers [h2, http/1.1], follows server choice
)

// h2HelperResult is the single line of machine-parseable output the helper
// prints to stdout. runH2Helper (the test-side driver) parses it back.
type h2HelperResult struct {
	OK         bool
	Proto      string // negotiated ALPN protocol ("h2" or "http/1.1")
	Status     int
	Body       string
	GRPCStatus string // "grpc-status" trailer value, or "" if absent/not requested
	GRPCMsg    string // "grpc-message" trailer value
	Err        string
}

// h2HelperMain is the client entrypoint. Args (os.Args[2:]):
//
//	alpnMode addr host capath reqKind path
//
// reqKind is "plain" (simple GET, expects a text body) or "grpc" (POST a
// grpc-framed body, expects grpc-status/grpc-message trailers back).
// It never returns -- always os.Exit.
func h2HelperMain(args []string) {
	if len(args) < 6 {
		fmt.Println("RESULT ok=false err=usage:_alpnMode_addr_host_capath_reqKind_path")
		os.Exit(2)
	}
	alpnMode := h2HelperALPN(args[0])
	addr := args[1]
	host := args[2]
	capath := args[3]
	reqKind := args[4]
	path := args[5]

	res := runH2Client(alpnMode, addr, host, capath, reqKind, path)
	printHelperResult(res)
	if res.OK {
		os.Exit(0)
	}
	os.Exit(1)
}

func runH2Client(alpnMode h2HelperALPN, addr, host, capath, reqKind, path string) h2HelperResult {
	caPEM, err := os.ReadFile(capath)
	if err != nil {
		return h2HelperResult{Err: fmt.Sprintf("read CA: %v", err)}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return h2HelperResult{Err: "AppendCertsFromPEM failed"}
	}

	baseTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	var client *http.Client
	switch alpnMode {
	case alpnH2Only:
		cfg := baseTLS.Clone()
		cfg.NextProtos = []string{"h2"}
		client = &http.Client{Transport: &http2.Transport{TLSClientConfig: cfg}}
	case alpnH1Only:
		cfg := baseTLS.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DialContext:       nil,
			ForceAttemptHTTP2: false,
		}}
	case alpnBoth:
		cfg := baseTLS.Clone()
		cfg.NextProtos = []string{"h2", "http/1.1"}
		t1 := &http.Transport{TLSClientConfig: cfg}
		if err := http2.ConfigureTransport(t1); err != nil {
			return h2HelperResult{Err: fmt.Sprintf("ConfigureTransport: %v", err)}
		}
		client = &http.Client{Transport: t1}
	default:
		return h2HelperResult{Err: fmt.Sprintf("unknown alpn mode %q", alpnMode)}
	}

	url := fmt.Sprintf("https://%s%s", addr, path)

	var req *http.Request
	if reqKind == "grpc" {
		frame := grpcFrame([]byte("agentjail-e2e-grpc-payload"))
		req, err = http.NewRequest(http.MethodPost, url, strings.NewReader(string(frame)))
		if err != nil {
			return h2HelperResult{Err: fmt.Sprintf("new request: %v", err)}
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("te", "trailers")
	} else {
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return h2HelperResult{Err: fmt.Sprintf("new request: %v", err)}
		}
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return h2HelperResult{Err: fmt.Sprintf("do: %v", err)}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return h2HelperResult{Err: fmt.Sprintf("read body: %v", err)}
	}

	res := h2HelperResult{
		OK:     true,
		Proto:  resp.Proto,
		Status: resp.StatusCode,
		Body:   sanitizeForLine(string(bodyBytes)),
	}
	if reqKind == "grpc" {
		res.GRPCStatus = resp.Trailer.Get("Grpc-Status")
		res.GRPCMsg = sanitizeForLine(resp.Trailer.Get("Grpc-Message"))
	}
	return res
}

// grpcFrame wraps payload in the standard gRPC length-prefixed message frame:
// 1 compressed-flag byte (0 == uncompressed) + 4 big-endian length bytes +
// payload. We are not linking google.golang.org/x/grpc (per the task's ADR
// constraint on new dependencies), so the payload itself is not a real
// protobuf message -- the test only asserts on the h2/gRPC transport framing
// and trailers, not on decoding a message schema.
func grpcFrame(payload []byte) []byte {
	n := len(payload)
	out := make([]byte, 5+n)
	out[0] = 0
	out[1] = byte(n >> 24)
	out[2] = byte(n >> 16)
	out[3] = byte(n >> 8)
	out[4] = byte(n)
	copy(out[5:], payload)
	return out
}

// sanitizeForLine strips newlines so a value can safely sit in the
// single-line RESULT output the parent test parses.
func sanitizeForLine(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// printHelperResult writes the RESULT line runH2Helper (test side) parses.
// Deliberately simple key=value pairs (no JSON) since this crosses the
// nsenter/timeout wrapper's stdout capture.
func printHelperResult(r h2HelperResult) {
	fmt.Printf("RESULT ok=%s proto=%s status=%s body=%s grpcstatus=%s grpcmsg=%s err=%s\n",
		strconv.FormatBool(r.OK),
		encodeField(r.Proto),
		strconv.Itoa(r.Status),
		encodeField(r.Body),
		encodeField(r.GRPCStatus),
		encodeField(r.GRPCMsg),
		encodeField(r.Err),
	)
}

// encodeField makes a value safe as a space-delimited key=value token: empty
// becomes "-", internal spaces are escaped so the line still splits cleanly.
func encodeField(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, " ", "\\x20")
}

// decodeField reverses encodeField.
func decodeField(s string) string {
	if s == "-" {
		return ""
	}
	return strings.ReplaceAll(s, "\\x20", " ")
}

// parseHelperResult parses one RESULT line printed by printHelperResult.
func parseHelperResult(line string) (h2HelperResult, error) {
	var r h2HelperResult
	fields := strings.Fields(line)
	found := false
	for _, f := range fields {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "RESULT", "ok":
			if kv[0] == "ok" {
				r.OK = kv[1] == "true"
				found = true
			}
		case "proto":
			r.Proto = decodeField(kv[1])
		case "status":
			n, _ := strconv.Atoi(kv[1])
			r.Status = n
		case "body":
			r.Body = decodeField(kv[1])
		case "grpcstatus":
			r.GRPCStatus = decodeField(kv[1])
		case "grpcmsg":
			r.GRPCMsg = decodeField(kv[1])
		case "err":
			r.Err = decodeField(kv[1])
		}
	}
	if !found {
		return r, fmt.Errorf("no RESULT line found in: %q", line)
	}
	return r, nil
}
