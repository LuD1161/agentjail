package mitm

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// RequestLog holds details about an intercepted HTTP request/response pair.
// RequestLog is defined in store.go — the MITM handler populates it.

const maxBodyScan = 1 << 20 // 1 MiB cap for body buffering during policy eval

// MITMHandler performs TLS termination, HTTP request/response inspection,
// and upstream forwarding for CONNECT tunnels.
type MITMHandler struct {
	CACert    *x509.Certificate
	CAKey     crypto.PrivateKey
	Logger    *slog.Logger
	OnRequest func(req *RequestLog) // called for each intercepted request
	Matcher   *netpolicy.Matcher    // optional: if set, operations are evaluated against templates
	// Audit records session-level facts about the interception itself, as
	// opposed to per-request logs (which go to OnRequest). Optional: nil means
	// the notice is logged but not filed. AGE-222.
	Audit audit.Emitter
	// Bodies sinks captured request/response bodies to files. Nil means the
	// hop is not recorded; it is never a reason to fail the request.
	// See ADR 0092-persist-request-bodies (D1).
	Bodies *BodyStore
	// SessionID groups every row of one shield launch. It must match Bodies'
	// session, which is the directory the bodies land in.
	SessionID string
	// OwnerPID is the shield process that owns this session; stamped onto every
	// row so the UI can decide "active" by liveness. See
	// ADR 0100-network-active-pid.
	OwnerPID int

	UpstreamTLSConfig *tls.Config // optional: override for upstream TLS (tests only)
	certCache         *hostCertCache
	// h2Noted keeps the ALPN downgrade notice to once per session. Atomic
	// because ClientHellos arrive on many connections concurrently.
	h2Noted atomic.Bool
}

// NewMITMHandler creates a handler with an initialized cert cache.
func NewMITMHandler(caCert *x509.Certificate, caKey crypto.PrivateKey, logger *slog.Logger, onRequest func(*RequestLog)) *MITMHandler {
	return &MITMHandler{
		CACert:    caCert,
		CAKey:     caKey,
		Logger:    logger,
		OnRequest: onRequest,
		certCache: newHostCertCache(),
	}
}

// Handle performs MITM for one CONNECT tunnel.
// clientConn is the raw TCP connection from the agent (after the 200 response
// has already been sent). host and port identify the upstream target.
func (h *MITMHandler) Handle(clientConn net.Conn, host, port string) {
	// Normalize once: the cert, the SNI, the dial address, the cache key and
	// the policy host must all mean the same thing by "host". AGE-220.
	target := ParseHostTarget(host)
	host = target.Host

	// Step 1+2: serve a leaf cert matching the client's SNI and complete the
	// TLS handshake.
	//
	// The leaf name is chosen from the ClientHello's SNI, not the caller's
	// `host`. SNI is the name the client actually verifies the cert against and
	// is present whenever the agent connects by hostname — even when the agent's
	// DNS did NOT go through the tunnel. On macOS the system resolver runs
	// out-of-band (a different process than the sandboxed agent), so the agent
	// dials the REAL IP and `host` here is that raw IP; signing the leaf for the
	// IP would fail the client's hostname check. Falling back to `host` covers
	// the SNI-less case (agent dialed by IP) and the DNS-VIP path (host is
	// already the hostname). See ADR 0105-mitm-sni-cert.
	//
	// NextProtos advertises h2 first, then http/1.1, in server-preference order
	// (Go picks by server preference, RFC 7301 §3.2), so a client that offers
	// both gets real h2. ADR 0077 (D4), AGE-222; serving h2 for real is AGE-223.
	var clientOfferedH2 bool
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := host
			if hello.ServerName != "" {
				name = hello.ServerName
			}
			// The ClientHello is the only place the client's raw ALPN offer is
			// visible; ConnectionState().NegotiatedProtocol reports what was
			// agreed. Record here, check the downgrade after Handshake below.
			if offersH2(hello.SupportedProtos) {
				clientOfferedH2 = true
			}
			if cert := h.certCache.get(name); cert != nil {
				return cert, nil
			}
			cert, err := SignHostCert(h.CACert, h.CAKey, name)
			if err != nil {
				h.Logger.Error("sign host cert failed", "host", name, "err", err)
				return nil, err
			}
			h.certCache.put(name, cert)
			return cert, nil
		},
	}
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		h.Logger.Warn("client TLS handshake failed", "host", host, "err", err)
		return
	}
	defer clientTLS.Close()

	// Adopt the SNI as the canonical host for upstream verification, dialing and
	// logging: it is the real destination name even when `host` arrived as a raw
	// IP (no VIP mapping). An empty SNI (agent dialed by IP) keeps the original.
	// See ADR 0105-mitm-sni-cert.
	if sni := clientTLS.ConnectionState().ServerName; sni != "" && sni != host {
		host = sni
		target = ParseHostTarget(sni)
	}

	negotiated := clientTLS.ConnectionState().NegotiatedProtocol
	// A client that offered h2 and did NOT get it is the only real downgrade
	// left: we advertise h2 first, so this means the handshake itself
	// overrode our preference, not that we chose not to serve it. See
	// alpn.go and AGE-223.
	if clientOfferedH2 && negotiated != "h2" {
		h.noteH2Downgrade(host, []string{"h2"})
	}

	// Step 3: prepare upstream TLS (verify against system roots).
	//
	// ServerName is set even for an IP: Go omits an IP from the SNI extension
	// itself, and uses ServerName to verify the cert's IP SAN. Clearing it
	// would skip verification, not fix it.
	upstreamTLS := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if h.UpstreamTLSConfig != nil {
		upstreamTLS = h.UpstreamTLSConfig.Clone()
		upstreamTLS.ServerName = host
	}

	// h2 takes over the connection entirely: http2.Server multiplexes streams
	// and http.Transport dials/pools upstream h2 connections per request, so
	// there is no single upstream conn to set up here the way h1 needs one.
	if negotiated == "h2" {
		h.serveH2(clientTLS, host, target, port, upstreamTLS)
		return
	}

	upstream, err := tls.Dial("tcp", target.DialAddr(port), upstreamTLS)
	if err != nil {
		h.Logger.Error("upstream TLS dial failed", "host", host, "port", port, "err", err)
		return
	}
	defer upstream.Close()

	clientBuf := bufio.NewReader(clientTLS)
	upstreamBuf := bufio.NewReader(upstream)

	// Step 4-9: loop for HTTP/1.1 keep-alive.
	for {
		reqLog := &RequestLog{
			Ts:        time.Now(),
			Host:      host,
			SessionID: h.SessionID,
			OwnerPID:  h.OwnerPID,
		}
		start := time.Now()

		// Captures are finished on every exit path, so a body already streamed
		// to disk is recorded even when the hop failed.
		// See ADR 0092-persist-request-bodies (D1).
		var reqCapture, respCapture *BodyCapture
		emitLog := func() {
			h.finishCaptures(reqLog, reqCapture, respCapture)
			h.emit(reqLog)
		}

		// Read request from client.
		req, err := http.ReadRequest(clientBuf)
		if err != nil {
			if err != io.EOF {
				h.Logger.Debug("read client request failed", "host", host, "err", err)
			}
			return
		}

		reqLog.Method = req.Method
		reqLog.Path = req.URL.RequestURI()
		reqLog.URL = fmt.Sprintf("https://%s%s", host, req.URL.RequestURI())
		reqLog.RequestHeaders = flattenHeaders(req.Header)

		// Expect: 100-continue -- the client sends no body until it is told to.
		// http.Server answers this for you; http.ReadRequest does not, so the
		// drain below would block on a body that never comes. Every large
		// upload (curl adds the header itself, as do S3 and Docker) hung.
		// AGE-226.
		//
		// The body is uploaded to us, not upstream: we still hold it, scan it,
		// and can deny before anything leaves the machine.
		if hasExpectContinue(req) {
			if _, werr := clientTLS.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n")); werr != nil {
				h.Logger.Debug("write 100-continue failed", "host", host, "err", werr)
				return
			}
			// Answered here, so it must not travel upstream: an upstream
			// interim 100 would be read back as this request's response.
			req.Header.Del("Expect")
		}

		// Buffer request body for policy evaluation (up to maxBodyScan).
		var bodyBuf []byte
		var fullBody io.Reader
		var bodyCount *countingReader
		if req.Body != nil {
			limited := io.LimitReader(req.Body, maxBodyScan+1)
			bodyBuf, err = io.ReadAll(limited)
			if err != nil {
				reqLog.Error = fmt.Sprintf("read request body: %v", err)
				reqLog.ElapsedMs = time.Since(start).Milliseconds()
				emitLog()
				return
			}
			reqCapture = h.startCapture(SideRequest, req.Header.Get("Content-Encoding"))
			// Exact only while the body fits the scan window; past that it is
			// the bytes seen so far, corrected once the body streams upstream.
			reqLog.RequestSize = int64(len(bodyBuf))
			if len(bodyBuf) > maxBodyScan {
				// Body exceeds scan cap: chain buffered portion with remaining stream.
				var src io.Reader = io.MultiReader(bytes.NewReader(bodyBuf), req.Body)
				if reqCapture != nil {
					src = io.TeeReader(src, reqCapture)
				}
				bodyCount = &countingReader{r: src}
				fullBody = bodyCount
				bodyBuf = bodyBuf[:maxBodyScan]
			} else {
				if reqCapture != nil {
					_, _ = reqCapture.Write(bodyBuf)
				}
				fullBody = bytes.NewReader(bodyBuf)
				req.Body.Close()
			}
		}

		// Run policy engine if a matcher is configured.
		denied := false
		if h.Matcher != nil {
			op := netpolicy.RecognizeHTTP(host, req, bodyBuf)
			reqLog.Service = op.Service
			reqLog.Verb = op.Verb
			reqLog.ResourceType = op.ResourceType

			if result := h.Matcher.Evaluate(op); result != nil {
				reqLog.PolicyAction = result.Action
				reqLog.PolicyTemplate = result.Template.ID
				reqLog.PolicyReason = result.Reason

				h.Logger.Info("policy eval",
					"host", host,
					"service", op.Service,
					"verb", op.Verb,
					"resource", op.ResourceType,
					"action", result.Action,
					"template", result.Template.ID,
				)

				if strings.EqualFold(result.Action, "deny") {
					denied = true
					denyBody, _ := json.Marshal(map[string]string{
						"error":    "blocked by agentjail network policy",
						"template": result.Template.ID,
						"reason":   result.Reason,
					})
					denyResp := &http.Response{
						StatusCode: http.StatusForbidden,
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: http.Header{
							"Content-Type":     {"application/json"},
							"X-Agentjail-Deny": {result.Template.ID},
						},
						Body:          io.NopCloser(bytes.NewReader(denyBody)),
						ContentLength: int64(len(denyBody)),
					}
					reqLog.StatusCode = http.StatusForbidden
					reqLog.ElapsedMs = time.Since(start).Milliseconds()
					if writeErr := denyResp.Write(clientTLS); writeErr != nil {
						reqLog.Error = fmt.Sprintf("write deny response: %v", writeErr)
					}
					emitLog()
					if req.Close {
						return
					}
					continue
				}
			}
		}

		if denied {
			continue
		}

		// Reconstruct request body for upstream forwarding.
		if fullBody != nil {
			req.Body = io.NopCloser(fullBody)
		}

		// Write request to upstream.
		writeReqErr := req.Write(upstream)
		// Only the streamed body knows its own length: RequestSize was capped at
		// the scan window until now, so every upload over 1 MiB recorded the same
		// wrong number and D2's byte budget undercounted. See AGE-243.
		if bodyCount != nil {
			reqLog.RequestSize = bodyCount.n
		}
		if writeReqErr != nil {
			reqLog.Error = fmt.Sprintf("write request upstream: %v", writeReqErr)
			reqLog.ElapsedMs = time.Since(start).Milliseconds()
			emitLog()
			return
		}

		// Read response from upstream.
		resp, err := http.ReadResponse(upstreamBuf, req)
		if err != nil {
			reqLog.Error = fmt.Sprintf("read upstream response: %v", err)
			reqLog.ElapsedMs = time.Since(start).Milliseconds()
			emitLog()
			return
		}

		reqLog.StatusCode = resp.StatusCode
		reqLog.ResponseHeaders = flattenHeaders(resp.Header)

		// Tee the response to disk as it passes. Buffering it before forwarding
		// would make the agent wait for the whole stream -- SSE model turns run
		// for seconds. See ADR 0092-persist-request-bodies (D1).
		respCapture = h.startCapture(SideResponse, resp.Header.Get("Content-Encoding"))
		counter := &countingWriter{}
		var sink io.Writer = counter
		if respCapture != nil {
			sink = io.MultiWriter(counter, respCapture)
		}
		resp.Body = io.NopCloser(io.TeeReader(resp.Body, sink))

		// Write response back to client.
		writeErr := resp.Write(clientTLS)
		reqLog.ResponseSize = counter.n
		resp.Body.Close()

		reqLog.ElapsedMs = time.Since(start).Milliseconds()

		if writeErr != nil {
			reqLog.Error = fmt.Sprintf("write response to client: %v", writeErr)
			emitLog()
			return
		}

		emitLog()

		// If either side signals close, stop.
		if req.Close || resp.Close {
			return
		}
	}
}

func (h *MITMHandler) emit(rl *RequestLog) {
	if h.OnRequest != nil {
		h.OnRequest(rl)
	}
}

// startCapture opens a body file, or returns nil: recording is not allowed to
// fail a request. See ADR 0092-persist-request-bodies (D1).
func (h *MITMHandler) startCapture(side Side, contentEncoding string) *BodyCapture {
	if h.Bodies == nil {
		return nil
	}
	c, err := h.Bodies.Create(side, contentEncoding)
	if err != nil {
		h.Logger.Warn("body capture unavailable", "err", err)
		return nil
	}
	return c
}

// finishCaptures normalizes both captures and records their paths on rl. It is
// idempotent: every exit path calls it, and only the first does the work.
func (h *MITMHandler) finishCaptures(rl *RequestLog, reqC *BodyCapture, respC *BodyCapture) {
	if h.Bodies == nil || rl.bodiesFinished {
		return
	}
	rl.bodiesFinished = true
	reqPath, reqRaw := h.finishOne(reqC)
	respPath, respRaw := h.finishOne(respC)
	rl.RequestBodyPath = reqPath
	rl.ResponseBodyPath = respPath
	rl.EncodingRaw = encodingRawSides(reqRaw, respRaw)
}

func (h *MITMHandler) finishOne(c *BodyCapture) (string, bool) {
	rel, raw, err := h.Bodies.Finish(c)
	if err != nil {
		// A short file is a partial capture, not a decode failure: keep the row.
		h.Logger.Warn("body capture incomplete", "path", rel, "err", err)
	}
	return rel, raw
}

// countingWriter counts bytes written to it without storing them.
type countingWriter struct {
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// countingReader counts bytes read through it without storing them, so a body
// streamed upstream can be measured without being buffered.
type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, vs := range h {
		flat[k] = strings.Join(vs, ", ")
	}
	return flat
}
