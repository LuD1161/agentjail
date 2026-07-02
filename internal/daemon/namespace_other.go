//go:build !linux

package daemon

import (
	"fmt"
	"log/slog"
)

// errUnsupported is returned on non-Linux platforms where network namespaces
// are not available.
var errUnsupported = fmt.Errorf("network namespace operations require Linux")

// stubNamespaceHandler is a no-op implementation for non-Linux platforms.
type stubNamespaceHandler struct {
	logger *slog.Logger
}

func newPlatformNamespaceHandler(_ AuditFunc, logger *slog.Logger) NamespaceHandler {
	return &stubNamespaceHandler{logger: logger}
}

func (h *stubNamespaceHandler) Create(_ CreateNamespaceReq) (*CreateNamespaceResp, error) {
	return nil, errUnsupported
}

func (h *stubNamespaceHandler) Destroy(_ DestroyNamespaceReq) error {
	return errUnsupported
}

func (h *stubNamespaceHandler) CleanupAll() {
	h.logger.Debug("namespace cleanup: no-op on this platform")
}
