package notify

import (
	"context"

	"github.com/gen2brain/beeep"
)

// notifier abstracts desktop notifications so tests can swap in a stub.
var notifier = func(title, message, appIcon string) error {
	return beeep.Notify(title, message, appIcon)
}

// Send dispatches a cross-platform desktop notification (macOS, Linux,
// Windows) via the beeep library. The context is accepted for API
// compatibility but is not currently used by beeep.
func Send(_ context.Context, title, message string) error {
	return notifier(title, message, "")
}
