package captureproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// maxBodyScan bounds how much of a request body is buffered for recognition
// (netpolicy.RecognizeHTTP) before the rest streams straight to upstream.
// Mirrors internal/mitm's scan cap so the two capture paths behave the same.
const maxBodyScan = 1 << 20 // 1 MiB

// Recorder persists one intercepted request. *mitm.RequestStore satisfies
// this in production; tests use a fake.
type Recorder interface {
	Log(*mitm.RequestLog) error
}

// Options configures a Gateway.
type Options struct {
	SessionID string
	OwnerPID  int
	// Agent and Cwd label the session on every row, mirroring the
	// mitm.MITMHandler fields of the same names.
	Agent string
	Cwd   string
	// ClaudeSession resolves late (see mitm.ClaudeSessionRef); nil is valid.
	ClaudeSession *mitm.ClaudeSessionRef
	Logger        *slog.Logger
	// Matcher is optional. Phase 1 leaves it nil (record-only); Phase 2 wires
	// policy evaluation at the call site marked in handle(). See AGE-81.
	Matcher *netpolicy.Matcher
	// Bodies is optional. When set, bodies persist through the same writer
	// internal/mitm uses (encryption + keychain fallback, ADR 0092/0095) --
	// one body-capture path in the codebase, this package just calls it.
	Bodies *mitm.BodyStore
	// Transport overrides the upstream RoundTripper. Nil uses default TLS
	// verification and no timeouts that would cut a long SSE stream.
	Transport http.RoundTripper
}

// Gateway is a per-session loopback reverse proxy: the agent's provider
// base-URL env var points here in plaintext, and Gateway forwards to target
// (typically over TLS) while recording every request/response through rec.
type Gateway struct {
	target *url.URL
	rec    Recorder
	opts   Options
	client *http.Client

	nonce    string
	baseURL  string
	listener net.Listener
	server   *http.Server
	cancel   context.CancelFunc
}

// New creates a Gateway that forwards to target. Call Start to bind and
// begin serving.
func New(target *url.URL, rec Recorder, opts Options) *Gateway {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Gateway{
		target: target,
		rec:    rec,
		opts:   opts,
		client: &http.Client{Transport: transport},
	}
}

// mintNonce generates the gateway's per-instance capability token. It is the
// only thing standing between a loopback port and the real upstream, so it
// must never be logged, stored, or echoed back in an error.
func mintNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("gateway: mint nonce: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// Start binds 127.0.0.1:0, mints the nonce, and begins serving. The returned
// baseURL is what the caller injects into the agent's provider base-URL env
// var: "http://127.0.0.1:<port>/aj~<nonce>".
func (g *Gateway) Start(ctx context.Context) (baseURL string, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("gateway: listen: %w", err)
	}
	nonce, err := mintNonce()
	if err != nil {
		_ = ln.Close()
		return "", err
	}

	innerCtx, cancel := context.WithCancel(ctx)
	g.listener = ln
	g.nonce = nonce
	g.cancel = cancel
	g.server = &http.Server{
		Handler:     http.HandlerFunc(g.handle),
		BaseContext: func(net.Listener) context.Context { return innerCtx },
	}

	port := ln.Addr().(*net.TCPAddr).Port
	g.baseURL = fmt.Sprintf("http://127.0.0.1:%d%s%s", port, gatewayNoncePrefix, nonce)

	go func() {
		if serveErr := g.server.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			g.opts.Logger.Warn("gateway: serve exited", "err", serveErr)
		}
	}()

	return g.baseURL, nil
}

// Close stops serving and cancels any in-flight requests.
func (g *Gateway) Close() error {
	if g.cancel != nil {
		g.cancel()
	}
	if g.server == nil {
		return nil
	}
	return g.server.Close()
}

// handle is the gateway's single entry point. Every request must carry the
// nonce prefix -- it is the session capability -- or it is rejected without
// being forwarded.
func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	prefix := gatewayNoncePrefix + g.nonce
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	stripped := strings.TrimPrefix(r.URL.Path, prefix)
	if stripped == "" {
		stripped = "/"
	}

	start := time.Now()
	reqLog := &mitm.RequestLog{
		Ts:              start,
		Host:            g.target.Host,
		Method:          r.Method,
		Path:            stripped,
		SessionID:       g.opts.SessionID,
		ClaudeSessionID: g.opts.ClaudeSession.Get(),
		OwnerPID:        g.opts.OwnerPID,
		Agent:           g.opts.Agent,
		Cwd:             g.opts.Cwd,
	}

	upstreamURL := *g.target
	upstreamURL.Path = g.target.JoinPath(stripped).Path
	upstreamURL.RawQuery = r.URL.RawQuery
	reqLog.URL = upstreamURL.String()

	reqLog.RequestHeaders = flattenHeaders(r.Header)

	var reqCapture *mitm.BodyCapture
	var respCapture *mitm.BodyCapture
	finish := func() {
		g.finishCaptures(reqLog, reqCapture, respCapture)
	}

	forwardBody, bodyBuf, sizeCounter := g.captureRequestBody(r, &reqCapture)

	// Same recognizer pipeline internal/mitm uses, so policy templates
	// evaluate identically regardless of capture path.
	op := netpolicy.RecognizeHTTP(g.target.Host, r, bodyBuf)
	reqLog.Service = op.Service
	reqLog.Verb = op.Verb
	reqLog.ResourceType = op.ResourceType

	// Phase 2: netpolicy.Evaluate here. See AGE-81.
	_ = g.opts.Matcher

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), forwardBody)
	if err != nil {
		reqLog.Error = fmt.Sprintf("build upstream request: %v", err)
		reqLog.ElapsedMs = time.Since(start).Milliseconds()
		finish()
		g.log(reqLog)
		http.Error(w, "gateway: bad upstream request", http.StatusBadGateway)
		return
	}
	outReq.Header = cloneForwardHeaders(r.Header)
	outReq.Host = upstreamURL.Host

	resp, err := g.client.Do(outReq)
	if sizeCounter != nil {
		reqLog.RequestSize = sizeCounter.n
	}
	if err != nil {
		reqLog.Error = fmt.Sprintf("upstream request failed: %v", err)
		reqLog.ElapsedMs = time.Since(start).Milliseconds()
		finish()
		g.log(reqLog)
		http.Error(w, "gateway: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	reqLog.ResponseHeaders = flattenHeaders(resp.Header)
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Connection") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	reqLog.StatusCode = resp.StatusCode

	respCapture = g.startCapture(mitm.SideResponse, resp.Header.Get("Content-Encoding"))
	flusher, canFlush := w.(http.Flusher)
	var respSize int64
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				reqLog.Error = fmt.Sprintf("write response to client: %v", werr)
				break
			}
			respSize += int64(n)
			if respCapture != nil {
				_, _ = respCapture.Write(buf[:n])
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				reqLog.Error = fmt.Sprintf("read upstream response: %v", rerr)
			}
			break
		}
	}
	reqLog.ResponseSize = respSize
	reqLog.ElapsedMs = time.Since(start).Milliseconds()

	finish()
	g.log(reqLog)
}

// captureRequestBody reads up to maxBodyScan bytes for recognition, then
// streams the rest unbuffered -- large uploads are never fully buffered.
// Mirrors internal/mitm.Handle. counter.n holds the exact body size once the
// upstream request has fully sent.
func (g *Gateway) captureRequestBody(r *http.Request, capture **mitm.BodyCapture) (forwardBody io.Reader, scanned []byte, counter *countingReader) {
	if r.Body == nil {
		return nil, nil, nil
	}
	limited := io.LimitReader(r.Body, maxBodyScan+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, nil
	}
	*capture = g.startCapture(mitm.SideRequest, r.Header.Get("Content-Encoding"))

	var src io.Reader
	if len(buf) > maxBodyScan {
		src = io.MultiReader(bytes.NewReader(buf), r.Body)
		scanned = buf[:maxBodyScan]
	} else {
		src = bytes.NewReader(buf)
		scanned = buf
	}
	if *capture != nil {
		src = io.TeeReader(src, *capture)
	}
	counter = &countingReader{r: src}
	return counter, scanned, counter
}

// startCapture opens a body file, or returns nil: recording must never fail
// the proxied request. Same contract as internal/mitm.MITMHandler.startCapture.
func (g *Gateway) startCapture(side mitm.Side, contentEncoding string) *mitm.BodyCapture {
	if g.opts.Bodies == nil {
		return nil
	}
	c, err := g.opts.Bodies.Create(side, contentEncoding)
	if err != nil {
		g.opts.Logger.Warn("gateway: body capture unavailable", "err", err)
		return nil
	}
	return c
}

// finishCaptures normalizes both captures and records their paths on rl.
func (g *Gateway) finishCaptures(rl *mitm.RequestLog, reqC, respC *mitm.BodyCapture) {
	if g.opts.Bodies == nil {
		return
	}
	reqPath, reqRaw := g.finishOne(reqC)
	respPath, respRaw := g.finishOne(respC)
	rl.RequestBodyPath = reqPath
	rl.ResponseBodyPath = respPath
	rl.EncodingRaw = combineEncodingRawSides(reqRaw, respRaw)
}

func (g *Gateway) finishOne(c *mitm.BodyCapture) (string, bool) {
	rel, raw, err := g.opts.Bodies.Finish(c)
	if err != nil {
		g.opts.Logger.Warn("gateway: body capture incomplete", "path", rel, "err", err)
	}
	return rel, raw
}

// combineEncodingRawSides mirrors internal/mitm's private encodingRawSides:
// the four EncodingRawSides values it combines into are exported, so this
// package computes the same result without needing another mitm export.
func combineEncodingRawSides(reqRaw, respRaw bool) mitm.EncodingRawSides {
	switch {
	case reqRaw && respRaw:
		return mitm.EncodingRawBoth
	case reqRaw:
		return mitm.EncodingRawRequest
	case respRaw:
		return mitm.EncodingRawResponse
	default:
		return mitm.EncodingRawNone
	}
}

// log calls the Recorder, redacting nothing extra here: mitm.RequestStore.Log
// redacts credential headers at the persistence boundary (ADR 0032). The
// nonce is never placed on rl in the first place (Path/URL/Host all carry
// the upstream-side values), so there is nothing gateway-specific to strip.
func (g *Gateway) log(rl *mitm.RequestLog) {
	if g.rec == nil {
		return
	}
	if err := g.rec.Log(rl); err != nil {
		g.opts.Logger.Warn("gateway: log request failed", "err", err)
	}
}

// cloneForwardHeaders copies h, dropping headers that must not travel
// upstream verbatim: Host is set separately, Connection is hop-by-hop, and
// Content-Length is recomputed by net/http from the body it is given.
func cloneForwardHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, vs := range h {
		flat[k] = strings.Join(vs, ", ")
	}
	return flat
}

// countingReader counts bytes read through it without buffering them, so a
// body streamed upstream past the scan window can still be sized.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
