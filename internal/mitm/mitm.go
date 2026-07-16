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
	"time"

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

	UpstreamTLSConfig *tls.Config // optional: override for upstream TLS (tests only)
	certCache         *hostCertCache
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

	// Step 1: get or generate a host cert signed by the CA.
	hostCert := h.certCache.get(host)
	if hostCert == nil {
		var err error
		hostCert, err = SignHostCert(h.CACert, h.CAKey, host)
		if err != nil {
			h.Logger.Error("sign host cert failed", "host", host, "err", err)
			return
		}
		h.certCache.put(host, hostCert)
	}

	// Step 2: wrap client conn with TLS server using the host cert.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*hostCert},
		MinVersion:   tls.VersionTLS12,
	}
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		h.Logger.Warn("client TLS handshake failed", "host", host, "err", err)
		return
	}
	defer clientTLS.Close()

	// Step 3: dial upstream with real TLS (verify against system roots).
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
			Ts:   time.Now(),
			Host: host,
		}
		start := time.Now()

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

		// Buffer request body for policy evaluation (up to maxBodyScan).
		var bodyBuf []byte
		var fullBody io.Reader
		if req.Body != nil {
			limited := io.LimitReader(req.Body, maxBodyScan+1)
			bodyBuf, err = io.ReadAll(limited)
			if err != nil {
				reqLog.Error = fmt.Sprintf("read request body: %v", err)
				reqLog.ElapsedMs = time.Since(start).Milliseconds()
				h.emit(reqLog)
				return
			}
			reqLog.RequestSize = int64(len(bodyBuf))
			if len(bodyBuf) > maxBodyScan {
				// Body exceeds scan cap: chain buffered portion with remaining stream.
				fullBody = io.MultiReader(bytes.NewReader(bodyBuf), req.Body)
				bodyBuf = bodyBuf[:maxBodyScan]
			} else {
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
							"Content-Type":    {"application/json"},
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
					h.emit(reqLog)
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
		if writeErr := req.Write(upstream); writeErr != nil {
			reqLog.Error = fmt.Sprintf("write request upstream: %v", writeErr)
			reqLog.ElapsedMs = time.Since(start).Milliseconds()
			h.emit(reqLog)
			return
		}

		// Read response from upstream.
		resp, err := http.ReadResponse(upstreamBuf, req)
		if err != nil {
			reqLog.Error = fmt.Sprintf("read upstream response: %v", err)
			reqLog.ElapsedMs = time.Since(start).Milliseconds()
			h.emit(reqLog)
			return
		}

		reqLog.StatusCode = resp.StatusCode
		reqLog.ResponseHeaders = flattenHeaders(resp.Header)

		// Count response body bytes without buffering.
		counter := &countingWriter{}
		resp.Body = io.NopCloser(io.TeeReader(resp.Body, counter))

		// Write response back to client.
		writeErr := resp.Write(clientTLS)
		reqLog.ResponseSize = counter.n
		resp.Body.Close()

		reqLog.ElapsedMs = time.Since(start).Milliseconds()

		if writeErr != nil {
			reqLog.Error = fmt.Sprintf("write response to client: %v", writeErr)
			h.emit(reqLog)
			return
		}

		h.emit(reqLog)

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

// countingWriter counts bytes written to it without storing them.
type countingWriter struct {
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, vs := range h {
		flat[k] = strings.Join(vs, ", ")
	}
	return flat
}
