package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// serveH2 takes over an already-negotiated h2 client connection. It mirrors
// the h1 loop in Handle: buffer for policy, forward, stream the response
// back, record. See AGE-223.
func (h *MITMHandler) serveH2(clientTLS *tls.Conn, host string, target HostTarget, port string, upstreamTLS *tls.Config) {
	dialAddr := target.DialAddr(port)

	// ForceAttemptHTTP2 + a TLS authority pinned to dialAddr replicates the h1
	// dial: same host verification, same target normalization (AGE-220), but
	// negotiated over ALPN so an upstream that cannot do h2 is served h1
	// transparently by the transport itself.
	//
	// One Transport per tunnel, not per stream or process-global: h2 streams
	// on the same tunnel share dialAddr, so pooling here (the Transport's own
	// h2 conn pool) gets connection reuse across streams for free. Scoping it
	// to the tunnel means CloseIdleConnections on return actually tears the
	// pool down instead of leaking it into a shared pool that outlives the
	// session -- srv.ServeConn blocks until the client conn closes, so the
	// defer fires exactly once, when this tunnel is really done.
	transport := &http.Transport{
		TLSClientConfig:   upstreamTLS,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()

	rh := &h2RecordingHandler{h: h, host: host, port: parsePort(port), dialAddr: dialAddr, transport: transport}
	srv := &http2.Server{}
	srv.ServeConn(clientTLS, &http2.ServeConnOpts{Handler: rh, Context: context.Background()})
}

// isStreamingRequest reports whether the request body may stay open past
// the point a unary request would already have hit EOF, so pre-draining it
// with io.ReadAll would risk blocking forever: a client-streaming/bidi RPC
// keeps sending, or waits on a response, before it half-closes. Two signals,
// either sufficient on its own:
//
//   - Content-Type starts with "application/grpc": gRPC is always
//     potentially streaming (client-streaming and bidi use the same framing
//     as unary), so treat every gRPC request this way regardless of
//     Content-Length.
//   - r.ContentLength < 0: the client did not declare a bounded length, so
//     there is no way to know the body will ever end on its own.
//
// Body-content policy is not evaluated for these; header/method/path policy
// still runs. See ADR 0102-mitm-serves-h2 (AGE-223).
func isStreamingRequest(r *http.Request) bool {
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/grpc") {
		return true
	}
	return r.ContentLength < 0
}

// hopByHopHeaders are connection-specific (RFC 9113 §8.2.2 forbids them on
// h2 entirely). golang.org/x/net/http2 strips Connection and rewrites
// Transfer-Encoding on the outgoing leg to upstream, but leaves the rest
// (and never touches the response leg back to the client) for the caller.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding",
	"TE", "Upgrade", "Trailer",
}

// stripHopByHop removes hop-by-hop headers in place, including any header
// named by a Connection field value (RFC 7230 §6.1), so neither the request
// forwarded upstream nor the response copied to the client carries framing
// headers that don't mean anything on h2.
func stripHopByHop(h http.Header) {
	if conn := h.Get("Connection"); conn != "" {
		for _, name := range strings.Split(conn, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// h2RecordingHandler is the http.Handler http2.Server.ServeConn dispatches
// each h2 stream to. One instance per CONNECT tunnel; transport is shared so
// upstream h2 connections are reused across streams on the same tunnel.
type h2RecordingHandler struct {
	h         *MITMHandler
	host      string
	port      netpolicy.Port
	dialAddr  string
	transport *http.Transport
}

func (rh *h2RecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := rh.h
	start := time.Now()
	reqLog := &RequestLog{
		Ts:              start,
		Host:            rh.host,
		SessionID:       h.SessionID,
		ClaudeSessionID: h.ClaudeSession.Get(),
		OwnerPID:        h.OwnerPID,
		Agent:           h.Agent,
		Cwd:             h.Cwd,
	}

	var reqCapture, respCapture *BodyCapture
	emitLog := func() {
		h.finishCaptures(reqLog, reqCapture, respCapture)
		h.emit(reqLog)
	}

	reqLog.Method = r.Method
	reqLog.Path = r.URL.RequestURI()
	reqLog.URL = fmt.Sprintf("https://%s%s", rh.host, r.URL.RequestURI())
	reqLog.RequestHeaders = flattenHeaders(r.Header)

	// Buffer request body for policy evaluation (up to maxBodyScan), exactly
	// like the h1 loop. h2 has no Expect:100-continue wrinkle: net/http2
	// answers interim responses itself before the handler runs.
	//
	// Streaming requests (see isStreamingRequest) are the exception: a
	// client-streaming/bidi caller holds the request stream open until it
	// has seen a response, so io.ReadAll on r.Body would block forever and
	// the request would never reach upstream. Never pre-drain those; stream
	// them upstream through the tee-capture path with an empty body slice
	// for policy instead. See ADR 0102-mitm-serves-h2 (AGE-223).
	var bodyBuf []byte
	var fullBody io.Reader
	var bodyCount *countingReader
	if r.Body != nil {
		reqCapture = h.startCapture(SideRequest, r.Header.Get("Content-Encoding"))
		if isStreamingRequest(r) {
			var src io.Reader = r.Body
			if reqCapture != nil {
				src = io.TeeReader(src, reqCapture)
			}
			bodyCount = &countingReader{r: src}
			fullBody = bodyCount
		} else {
			limited := io.LimitReader(r.Body, maxBodyScan+1)
			var err error
			bodyBuf, err = io.ReadAll(limited)
			if err != nil {
				reqLog.Error = fmt.Sprintf("read request body: %v", err)
				reqLog.ElapsedMs = time.Since(start).Milliseconds()
				w.WriteHeader(http.StatusBadGateway)
				emitLog()
				return
			}
			reqLog.RequestSize = int64(len(bodyBuf))
			if len(bodyBuf) > maxBodyScan {
				// Body exceeds scan cap: chain the buffered portion with the
				// remaining stream, same as h1.
				var src io.Reader = io.MultiReader(bytes.NewReader(bodyBuf), r.Body)
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
			}
		}
	}

	// Run the same policy engine the h1 loop runs, so a deny fires identically
	// regardless of which protocol carried the request.
	if h.Matcher != nil {
		op := netpolicy.RecognizeHTTPAt(rh.host, rh.port, r, bodyBuf)
		reqLog.Service = op.Service
		reqLog.Verb = op.Verb
		reqLog.ResourceType = op.ResourceType

		if result := h.Matcher.Evaluate(op); result != nil {
			reqLog.PolicyAction = result.Action
			reqLog.PolicyTemplate = result.Template.ID
			reqLog.PolicyReason = result.Reason

			h.Logger.Info("policy eval",
				"host", rh.host,
				"service", op.Service,
				"verb", op.Verb,
				"resource", op.ResourceType,
				"action", result.Action,
				"template", result.Template.ID,
				"proto", "h2",
			)

			if strings.EqualFold(result.Action, "deny") {
				denyBody, _ := json.Marshal(map[string]string{
					"error":    "blocked by agentjail network policy",
					"template": result.Template.ID,
					"reason":   result.Reason,
				})
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Agentjail-Deny", result.Template.ID)
				w.WriteHeader(http.StatusForbidden)
				w.Write(denyBody)

				reqLog.StatusCode = http.StatusForbidden
				reqLog.ElapsedMs = time.Since(start).Milliseconds()
				emitLog()
				return
			}
		}
	}

	if fullBody != nil {
		r.Body = io.NopCloser(fullBody)
	}

	outReq, err := rh.buildUpstreamRequest(r)
	if err != nil {
		reqLog.Error = fmt.Sprintf("build upstream request: %v", err)
		reqLog.ElapsedMs = time.Since(start).Milliseconds()
		w.WriteHeader(http.StatusBadGateway)
		emitLog()
		return
	}

	resp, err := rh.transport.RoundTrip(outReq)
	if bodyCount != nil {
		reqLog.RequestSize = bodyCount.n
	}
	if err != nil {
		reqLog.Error = fmt.Sprintf("upstream request: %v", err)
		reqLog.ElapsedMs = time.Since(start).Milliseconds()
		w.WriteHeader(http.StatusBadGateway)
		emitLog()
		return
	}
	defer resp.Body.Close()

	reqLog.StatusCode = resp.StatusCode
	reqLog.ResponseHeaders = flattenHeaders(resp.Header)

	respCapture = h.startCapture(SideResponse, resp.Header.Get("Content-Encoding"))
	counter := &countingWriter{}
	var sink io.Writer = counter
	if respCapture != nil {
		sink = io.MultiWriter(counter, respCapture)
	}

	stripHopByHop(resp.Header)
	for k, vs := range resp.Header {
		w.Header()[k] = vs
	}
	// Pre-declare trailer field names so the h2 responseWriter accepts values
	// set on them after the body is written (RFC 9113 §8.1: trailers are a
	// second HEADERS frame with no fixed schema, so the names must be known
	// before WriteHeader flushes the first one).
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	var writeErr error
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := sink.Write(buf[:n]); werr != nil && writeErr == nil {
				writeErr = werr
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				writeErr = werr
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				writeErr = rerr
			}
			break
		}
	}
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	reqLog.ResponseSize = counter.n
	reqLog.ElapsedMs = time.Since(start).Milliseconds()
	if writeErr != nil {
		reqLog.Error = fmt.Sprintf("write response to client: %v", writeErr)
	}
	emitLog()
}

// buildUpstreamRequest clones the client's request onto the pinned upstream
// authority. RequestURI must be cleared: it is only valid on a server-read
// request, and http.Transport rejects a client request that carries it.
func (rh *h2RecordingHandler) buildUpstreamRequest(r *http.Request) (*http.Request, error) {
	outURL := &url.URL{
		Scheme:   "https",
		Host:     rh.dialAddr,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		return nil, err
	}
	outReq.Host = rh.host
	outReq.Header = r.Header.Clone()
	stripHopByHop(outReq.Header)
	outReq.ContentLength = r.ContentLength
	// Share r.Trailer rather than cloning it: net/http2's server fills the
	// map in place once the client's request body reaches EOF (see
	// stream.copyTrailersToHandlerRequest), which for a body past
	// maxBodyScan happens mid-RoundTrip, after buildUpstreamRequest already
	// returned. A Clone taken here would freeze the pre-fill, all-nil state
	// and drop every trailer on a streamed body.
	outReq.Trailer = r.Trailer
	return outReq, nil
}
