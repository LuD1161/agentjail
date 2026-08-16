//go:build !linux && !darwin

package hostproxy

import (
	"context"
	"time"
)

type platformExecutor struct{}

func (platformExecutor) Execute(context.Context, Target, string, time.Duration, int, func(int)) Result {
	return Result{ExitCode: -1, Reason: "unsupported_platform"}
}
