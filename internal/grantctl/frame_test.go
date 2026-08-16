package grantctl

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func paddedRequestFrame(t *testing.T, size int) []byte {
	t.Helper()
	prefix := `{"type":"grant_list","future_padding":"`
	suffix := `"}` + "\n"
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		t.Fatalf("frame size %d is too small", size)
	}
	frame := []byte(prefix + strings.Repeat("x", padding) + suffix)
	if len(frame) != size {
		t.Fatalf("constructed frame = %d bytes, want %d", len(frame), size)
	}
	return frame
}

func TestReadRequestFrameAdversarial(t *testing.T) {
	invalidUTF8 := append([]byte(`{"type":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}`+"\n")...)
	tests := []struct {
		name     string
		frame    []byte
		wantErr  error
		wantType RequestType
	}{
		{name: "empty", wantErr: ErrFrameMissingDelimiter},
		{name: "newline only", frame: []byte("\n"), wantErr: ErrFrameMalformedJSON},
		{name: "exact maximum", frame: paddedRequestFrame(t, MaxControlMsgBytes), wantType: ReqGrantList},
		{name: "maximum plus one", frame: paddedRequestFrame(t, MaxControlMsgBytes+1), wantErr: ErrFrameTooLarge},
		{name: "missing delimiter", frame: []byte(`{"type":"grant_list"}`), wantErr: ErrFrameMissingDelimiter},
		{name: "raw newline in pretty JSON", frame: []byte("{\n  \"type\":\"grant_list\"\n}\n"), wantErr: ErrFrameMalformedJSON},
		{name: "allowed terminal padding", frame: []byte("{\"type\":\"grant_list\"} \t\r\n"), wantType: ReqGrantList},
		{name: "junk", frame: []byte("not-json\n"), wantErr: ErrFrameMalformedJSON},
		{name: "second value before delimiter", frame: []byte("{\"type\":\"grant_list\"} {\"type\":\"grant_deny\"}\n"), wantErr: ErrFrameTrailingData},
		{name: "invalid UTF-8", frame: invalidUTF8, wantErr: ErrFrameInvalidUTF8},
		{name: "null envelope", frame: []byte("null\n"), wantErr: ErrFrameMalformedJSON},
		{name: "unknown additive field", frame: []byte("{\"type\":\"grant_list\",\"future_envelope\":true}\n"), wantType: ReqGrantList},
		{name: "second frame ignored", frame: []byte("{\"type\":\"grant_list\"}\n{\"type\":\"grant_deny\"}\n"), wantType: ReqGrantList},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := ReadRequestFrame(bytes.NewReader(test.frame))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ReadRequestFrame error = %v, want %v", err, test.wantErr)
			}
			if err == nil && request.Type != test.wantType {
				t.Fatalf("request type = %q, want %q", request.Type, test.wantType)
			}
		})
	}
}

type fragmentedFrameReader struct {
	data  []byte
	chunk int
}

func (r *fragmentedFrameReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(r.data), r.chunk, len(p))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestReadRequestFrameFragmented(t *testing.T) {
	frame := []byte("{\"type\":\"grant_approve\",\"grant_id\":\"g1\"}\n")
	request, err := ReadRequestFrame(&fragmentedFrameReader{data: frame, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	if request.Type != ReqGrantApprove || request.GrantID != "g1" {
		t.Fatalf("fragmented request = %+v", request)
	}
}

type chunkedFrameReaderSpy struct {
	data      []byte
	requested []int
	consumed  int
}

func (r *chunkedFrameReaderSpy) Read(p []byte) (int, error) {
	r.requested = append(r.requested, len(p))
	if r.consumed == len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.consumed:])
	r.consumed += n
	return n, nil
}

func TestReadRequestFrameUsesBoundedChunksAndDecodesOnlyFirst(t *testing.T) {
	first := []byte("{\"type\":\"grant_list\"}\n")
	second := []byte("{\"type\":\"grant_deny\"}\n")
	reader := &chunkedFrameReaderSpy{data: append(append([]byte(nil), first...), second...)}

	request, err := ReadRequestFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if request.Type != ReqGrantList {
		t.Fatalf("request type = %q", request.Type)
	}
	if len(reader.requested) != 1 {
		t.Fatalf("underlying reads = %d, want one bounded chunk", len(reader.requested))
	}
	for i, size := range reader.requested {
		if size != controlFrameReadChunkBytes {
			t.Fatalf("underlying read %d requested %d bytes, want %d", i, size, controlFrameReadChunkBytes)
		}
	}
}

type terminalEOFFrameReader struct {
	data []byte
}

func (r *terminalEOFFrameReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	if len(r.data) == 0 {
		return 1, io.EOF
	}
	return 1, nil
}

func TestReadRequestFrameAcceptsDelimiterReturnedWithEOF(t *testing.T) {
	reader := &terminalEOFFrameReader{data: []byte("{\"type\":\"grant_list\"}\n")}
	request, err := ReadRequestFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if request.Type != ReqGrantList {
		t.Fatalf("request type = %q", request.Type)
	}
}

func TestReadResponseFrameToleratesUnknownAdditiveField(t *testing.T) {
	response, err := ReadResponseFrame(strings.NewReader("{\"ok\":true,\"future_envelope\":{\"enabled\":true}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("response = %+v", response)
	}
}

type shortFrameWriter struct {
	bytes.Buffer
	chunk int
}

func (w *shortFrameWriter) Write(p []byte) (int, error) {
	if len(p) > w.chunk {
		p = p[:w.chunk]
	}
	return w.Buffer.Write(p)
}

func TestWriteRequestFrameCompletesShortWrites(t *testing.T) {
	w := &shortFrameWriter{chunk: 3}
	want := Request{Type: ReqGrantRequest, Host: "api.example.test", Reason: "line one\nline two"}
	if err := WriteRequestFrame(w, want); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(w.Bytes(), []byte{'\n'}) != 1 || !bytes.HasSuffix(w.Bytes(), []byte{'\n'}) {
		t.Fatalf("request frame delimiter = %q", w.Bytes())
	}
	if !bytes.Contains(w.Bytes(), []byte(`line one\nline two`)) {
		t.Fatalf("string newline was not JSON-escaped: %q", w.Bytes())
	}
	got, err := ReadRequestFrame(bytes.NewReader(w.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Host != want.Host || got.Reason != want.Reason {
		t.Fatalf("request round trip = %+v, want %+v", got, want)
	}
}

func TestWriteRequestFrameChecksSizeBeforeWrite(t *testing.T) {
	var dst bytes.Buffer
	err := WriteRequestFrame(&dst, Request{Type: ReqGrantRequest, Reason: strings.Repeat("x", MaxControlMsgBytes)})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteRequestFrame error = %v, want ErrFrameTooLarge", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("oversized request wrote %d bytes", dst.Len())
	}
}

func TestWriteResponseFrameReplacesOversizeBeforeWrite(t *testing.T) {
	const marker = "must-not-leak-original-prefix"
	response := Response{
		OK: true,
		Grants: []GrantInfo{{
			GrantID: "g1",
			Reason:  strings.Repeat(marker, MaxControlMsgBytes/len(marker)+1),
		}},
	}
	var dst bytes.Buffer
	if err := WriteResponseFrame(&dst, response); err != nil {
		t.Fatal(err)
	}
	if dst.Len() > MaxControlMsgBytes || bytes.Count(dst.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("refusal frame size/delimiter = %d/%d", dst.Len(), bytes.Count(dst.Bytes(), []byte{'\n'}))
	}
	if bytes.Contains(dst.Bytes(), []byte(marker)) {
		t.Fatal("oversized response prefix was written before the refusal")
	}
	got, err := ReadResponseFrame(bytes.NewReader(dst.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Error != oversizedResponseMessage || got.Grants != nil {
		t.Fatalf("oversized response refusal = %+v", got)
	}
}
