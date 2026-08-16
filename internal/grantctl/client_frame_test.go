package grantctl

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func startClientFrameServer(t *testing.T, serve func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	sock := shortSock(t, "frame.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		request, err := ReadRequestFrame(conn)
		if err != nil {
			done <- fmt.Errorf("read request: %w", err)
			return
		}
		if request.Type != ReqGrantList {
			done <- fmt.Errorf("request type = %q", request.Type)
			return
		}
		done <- serve(conn)
	}()
	return sock, done
}

func waitClientFrameServer(t *testing.T, done <-chan error) {
	t.Helper()
	if err := <-done; err != nil {
		t.Fatalf("fake server: %v", err)
	}
}

func writeTestFrame(conn net.Conn, frame []byte, chunk int) error {
	for len(frame) > 0 {
		n := min(len(frame), chunk)
		written, err := conn.Write(frame[:n])
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("zero-byte write")
		}
		frame = frame[written:]
	}
	return nil
}

func requireFramePeerClosed(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n != 0 || err == nil {
		return fmt.Errorf("peer remained open: n=%d err=%v", n, err)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return fmt.Errorf("peer timed out instead of closing: %w", err)
	}
	return nil
}

func TestRoundTripFrameRejectsTrailingJunk(t *testing.T) {
	sock, done := startClientFrameServer(t, func(conn net.Conn) error {
		return writeTestFrame(conn, []byte("{\"ok\":true}junk\n"), 64)
	})
	_, err := roundTrip(sock, Request{Type: ReqGrantList}, time.Second)
	if !errors.Is(err, ErrFrameTrailingData) {
		t.Fatalf("roundTrip error = %v, want ErrFrameTrailingData", err)
	}
	waitClientFrameServer(t, done)
}

func TestRoundTripFrameConsumesOnlyFirstResponse(t *testing.T) {
	sock, done := startClientFrameServer(t, func(conn net.Conn) error {
		if err := writeTestFrame(conn, []byte("{\"ok\":true}\n{\"ok\":false,\"error\":\"must be ignored\"}\n"), 64); err != nil {
			return err
		}
		return requireFramePeerClosed(conn)
	})
	response, err := roundTrip(sock, Request{Type: ReqGrantList}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Error != "" {
		t.Fatalf("roundTrip interpreted a second response: %+v", response)
	}
	waitClientFrameServer(t, done)
}

func TestRoundTripFrameRejectsOverflow(t *testing.T) {
	sock, done := startClientFrameServer(t, func(conn net.Conn) error {
		prefix := []byte(`{"ok":true}`)
		frame := append(prefix, bytes.Repeat([]byte{' '}, MaxControlMsgBytes-len(prefix))...)
		frame = append(frame, '\n')
		return writeTestFrame(conn, frame, len(frame))
	})
	_, err := roundTrip(sock, Request{Type: ReqGrantList}, time.Second)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("roundTrip error = %v, want ErrFrameTooLarge", err)
	}
	waitClientFrameServer(t, done)
}

func TestRoundTripFrameAcceptsFragmentedResponse(t *testing.T) {
	sock, done := startClientFrameServer(t, func(conn net.Conn) error {
		return writeTestFrame(conn, []byte("{\"ok\":true}\n"), 1)
	})
	response, err := roundTrip(sock, Request{Type: ReqGrantList}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("fragmented response = %+v", response)
	}
	waitClientFrameServer(t, done)
}

func TestRoundTripFrameTimeout(t *testing.T) {
	release := make(chan struct{})
	sock, done := startClientFrameServer(t, func(net.Conn) error {
		<-release
		return nil
	})
	_, err := roundTrip(sock, Request{Type: ReqGrantList}, 50*time.Millisecond)
	close(release)
	waitClientFrameServer(t, done)
	if err == nil {
		t.Fatal("expected response timeout")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("roundTrip timeout = %T %v", err, err)
	}
}

func TestRoundTripFrameRequestIsCompactAndDelimited(t *testing.T) {
	sock := shortSock(t, "request-frame.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	type readResult struct {
		frame []byte
		err   error
	}
	received := make(chan readResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			received <- readResult{err: acceptErr}
			return
		}
		defer conn.Close()
		payload, readErr := readDelimitedFrame(conn)
		if readErr != nil {
			received <- readResult{err: readErr}
			return
		}
		received <- readResult{frame: append(payload, '\n')}
		_ = WriteResponseFrame(conn, Response{OK: true})
	}()

	request := Request{Type: ReqGrantList, Reason: "line one\nline two"}
	if _, err := roundTrip(sock, request, time.Second); err != nil {
		t.Fatal(err)
	}
	result := <-received
	if result.err != nil {
		t.Fatal(result.err)
	}
	frame := result.frame
	if !bytes.HasSuffix(frame, []byte{'\n'}) || bytes.Count(frame, []byte{'\n'}) != 1 {
		t.Fatalf("request frame delimiter = %q", frame)
	}
	if bytes.Contains(frame[:len(frame)-1], []byte{'\n'}) || !strings.Contains(string(frame), `line one\nline two`) {
		t.Fatalf("request frame is not compact/escaped: %q", frame)
	}
}
