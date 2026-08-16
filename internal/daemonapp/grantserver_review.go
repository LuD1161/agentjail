package daemonapp

import (
	"fmt"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
)

// reviewSnapshotProjector is the daemon-owned seam for the read-only menu
// projection; grantctl retains its semantics. See ADR 0133-macos-menu-review.
type reviewSnapshotProjector interface {
	ReviewSnapshot(time.Time) grantctl.ReviewSnapshotV1
}

func reviewSnapshotResponse(projector reviewSnapshotProjector, version grantctl.ProtocolVersion, now time.Time) grantctl.Response {
	switch version {
	case 0:
		return grantctl.Response{OK: false, Error: "review_snapshot requires protocol_version"}
	case grantctl.ReviewProtocolVersion:
		snapshot := projector.ReviewSnapshot(now)
		return grantctl.Response{OK: true, ReviewSnapshot: &snapshot}
	default:
		return grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported review protocol version %d", version)}
	}
}
