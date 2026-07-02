package notify

import (
	"context"
	"errors"
	"testing"
)

func TestSend_DelegatesToNotifier(t *testing.T) {
	var gotTitle, gotMessage, gotIcon string

	orig := notifier
	defer func() { notifier = orig }()

	notifier = func(title, message, appIcon string) error {
		gotTitle = title
		gotMessage = message
		gotIcon = appIcon
		return nil
	}

	err := Send(context.Background(), "Test Title", "Test Message")
	if err != nil {
		t.Fatalf("Send returned unexpected error: %v", err)
	}

	if gotTitle != "Test Title" {
		t.Errorf("expected title %q, got %q", "Test Title", gotTitle)
	}
	if gotMessage != "Test Message" {
		t.Errorf("expected message %q, got %q", "Test Message", gotMessage)
	}
	if gotIcon != "" {
		t.Errorf("expected empty icon, got %q", gotIcon)
	}
}

func TestSend_PropagatesError(t *testing.T) {
	orig := notifier
	defer func() { notifier = orig }()

	want := errors.New("notification failed")
	notifier = func(_, _, _ string) error { return want }

	err := Send(context.Background(), "Title", "Message")
	if !errors.Is(err, want) {
		t.Errorf("expected error %v, got %v", want, err)
	}
}
