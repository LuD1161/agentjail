package mitm

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// TestH2RequestTrailersReachUpstream is the common case: a small body, fully
// buffered before buildUpstreamRequest runs, so the trailer values are
// already on r.Trailer by the time the upstream request is built.
func TestH2RequestTrailersReachUpstream(t *testing.T) {
	var gotTrailer string
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		gotTrailer = r.Trailer.Get("X-Client-Trailer")
		w.WriteHeader(http.StatusOK)
	}))

	tn := newH2Tunnel(t, upstream, nil)
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", "https://x/upload", pr)
	req.Trailer = http.Header{"X-Client-Trailer": nil}
	go func() {
		io.WriteString(pw, "small body")
		req.Trailer.Set("X-Client-Trailer", "trailer-value")
		pw.Close()
	}()

	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if gotTrailer != "trailer-value" {
		t.Errorf("upstream saw X-Client-Trailer = %q, want %q", gotTrailer, "trailer-value")
	}
}

// TestH2RequestTrailersSurviveStreamedBody mutation-probes the fix: a body
// past maxBodyScan takes the streamed path, where buildUpstreamRequest runs
// before the client's body (and therefore its trailer) has been fully read.
// Cloning r.Trailer at that point (the pre-fix code) freezes the all-nil
// state; sharing the map lets net/http2's in-place fill reach outReq.Trailer
// once the stream drains. Without the fix this test fails.
func TestH2RequestTrailersSurviveStreamedBody(t *testing.T) {
	var gotSize int64
	var gotTrailer string
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		gotSize = n
		gotTrailer = r.Trailer.Get("X-Client-Trailer")
		w.WriteHeader(http.StatusOK)
	}))

	tn := newH2Tunnel(t, upstream, nil)
	bodyLen := maxBodyScan + (64 << 10)
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", "https://x/upload", pr)
	req.Trailer = http.Header{"X-Client-Trailer": nil}
	go func() {
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for sent := 0; sent < bodyLen; sent += len(chunk) {
			pw.Write(chunk)
		}
		req.Trailer.Set("X-Client-Trailer", "trailer-survived-stream")
		pw.Close()
	}()

	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if gotSize != int64(bodyLen) {
		t.Fatalf("upstream received %d bytes, want %d: forwarding is broken, "+
			"so the trailer assertion below would be meaningless", gotSize, bodyLen)
	}
	if gotTrailer != "trailer-survived-stream" {
		t.Errorf("upstream saw X-Client-Trailer = %q, want %q (streamed body dropped the trailer)",
			gotTrailer, "trailer-survived-stream")
	}
}
