// Package schedule runs small, process-local background jobs.
package schedule

import (
	"context"
	"time"
)

// Daily runs job once immediately and then after each local calendar midnight.
// The job runs serially: a slow invocation cannot overlap the next one.
func Daily(ctx context.Context, job func(context.Context)) {
	daily(ctx, time.Now, time.Local, wait, job)
}

type waitFunc func(context.Context, time.Duration) bool

func daily(ctx context.Context, now func() time.Time, location *time.Location, waitFor waitFunc, job func(context.Context)) {
	if job == nil || ctx.Err() != nil {
		return
	}

	job(ctx)
	for ctx.Err() == nil {
		if !waitFor(ctx, untilNextMidnight(now(), location)) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		job(ctx)
	}
}

func untilNextMidnight(now time.Time, location *time.Location) time.Duration {
	if location == nil {
		location = time.Local
	}
	localNow := now.In(location)
	next := time.Date(localNow.Year(), localNow.Month(), localNow.Day()+1, 0, 0, 0, 0, location)
	return next.Sub(localNow)
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
