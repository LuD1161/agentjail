package grantctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Frame parsing errors are stable outcomes for the control-plane boundary.
var (
	ErrFrameMissingDelimiter = errors.New("control frame missing newline delimiter")
	ErrFrameTooLarge         = errors.New("control frame exceeds maximum size")
	ErrFrameInvalidUTF8      = errors.New("control frame is not valid UTF-8")
	ErrFrameMalformedJSON    = errors.New("control frame contains malformed JSON")
	ErrFrameTrailingData     = errors.New("control frame contains trailing data")
)

const oversizedResponseMessage = "control response exceeds maximum frame size"

// Chunking bounds pre-auth syscall work; bytes after the first LF are never
// decoded. See ADR 0133-macos-menu-review.
const controlFrameReadChunkBytes = 4 * 1024

// ReadRequestFrame reads and decodes one bounded Request frame.
func ReadRequestFrame(r io.Reader) (Request, error) {
	return readControlFrame[Request](r)
}

// ReadResponseFrame reads and decodes one bounded Response frame.
func ReadResponseFrame(r io.Reader) (Response, error) {
	return readControlFrame[Response](r)
}

// WriteRequestFrame encodes and completely writes one bounded Request frame.
func WriteRequestFrame(w io.Writer, request Request) error {
	frame, err := marshalControlFrame(request)
	if err != nil {
		return fmt.Errorf("encode control request frame: %w", err)
	}
	return writeFull(w, frame)
}

// WriteResponseFrame encodes and completely writes one bounded Response frame.
// An oversized response is replaced before writing with one bounded refusal.
func WriteResponseFrame(w io.Writer, response Response) error {
	frame, err := marshalControlFrame(response)
	if errors.Is(err, ErrFrameTooLarge) {
		frame, err = marshalControlFrame(Response{OK: false, Error: oversizedResponseMessage})
		if err != nil {
			return fmt.Errorf("encode oversized control response refusal: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("encode control response frame: %w", err)
	}
	return writeFull(w, frame)
}

type controlFrameMessage interface {
	Request | Response
}

func readControlFrame[T controlFrameMessage](r io.Reader) (T, error) {
	var message T
	payload, err := readDelimitedFrame(r)
	if err != nil {
		return message, err
	}
	if !utf8.Valid(payload) {
		return message, ErrFrameInvalidUTF8
	}

	trimmed := bytes.TrimLeft(payload, " \t\r")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return message, ErrFrameMalformedJSON
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&message); err != nil {
		return message, fmt.Errorf("%w: %v", ErrFrameMalformedJSON, err)
	}
	tail := payload[int(decoder.InputOffset()):]
	if len(bytes.Trim(tail, " \t\r")) != 0 {
		return message, ErrFrameTrailingData
	}
	return message, nil
}

func readDelimitedFrame(r io.Reader) ([]byte, error) {
	frame := make([]byte, MaxControlMsgBytes+1)
	used := 0
	for used < len(frame) {
		readSize := min(controlFrameReadChunkBytes, len(frame)-used)
		n, err := r.Read(frame[used : used+readSize])
		if n < 0 || n > readSize {
			return nil, fmt.Errorf("read control frame: invalid read count %d", n)
		}
		if n > 0 {
			if delimiter := bytes.IndexByte(frame[used:used+n], '\n'); delimiter >= 0 {
				frameSize := used + delimiter + 1
				if frameSize > MaxControlMsgBytes {
					return nil, ErrFrameTooLarge
				}
				return frame[:frameSize-1], nil
			}
			used += n
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if used > MaxControlMsgBytes {
					return nil, ErrFrameTooLarge
				}
				return nil, ErrFrameMissingDelimiter
			}
			return nil, fmt.Errorf("read control frame: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("read control frame: %w", io.ErrNoProgress)
		}
	}
	return nil, ErrFrameTooLarge
}

func marshalControlFrame[T controlFrameMessage](message T) ([]byte, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(payload)+1 > MaxControlMsgBytes {
		return nil, ErrFrameTooLarge
	}
	return append(payload, '\n'), nil
}

func writeFull(w io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n < 0 || n > len(frame) {
			return fmt.Errorf("write control frame: invalid write count %d", n)
		}
		frame = frame[n:]
		if err != nil {
			return fmt.Errorf("write control frame: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("write control frame: %w", io.ErrShortWrite)
		}
	}
	return nil
}
