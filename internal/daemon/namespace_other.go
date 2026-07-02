//go:build !linux && !darwin

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

func (h *stubNamespaceHandler) Destroy(req DestroyNamespaceReq) error {
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	// Create always returns errUnsupported on this platform, so no namespace
	// can ever exist. Honour the idempotency contract: destroying a
	// non-existent session returns nil.
	return nil
}

func (h *stubNamespaceHandler) CleanupAll() {
	h.logger.Debug("namespace cleanup: no-op on this platform")
}
