package schedule

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestDailyRunsAtStartupThenWaits(t *testing.T) {
	now := time.Date(2026, time.September, 2, 9, 30, 0, 0, time.UTC)
	var runs int
	var waited time.Duration

	daily(context.Background(), func() time.Time { return now }, time.UTC,
		func(_ context.Context, duration time.Duration) bool {
			waited = duration
			return false
		},
		func(context.Context) { runs++ },
	)

	if runs != 1 {
		t.Fatalf("startup runs = %d, want 1", runs)
	}
	if want := 14*time.Hour + 30*time.Minute; waited != want {
		t.Fatalf("wait = %s, want %s", waited, want)
	}
}

func TestDailyCancellationStopsWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{})
	done := make(chan struct{})
	var runs atomic.Int64

	go func() {
		daily(ctx, time.Now, time.UTC,
			func(ctx context.Context, _ time.Duration) bool {
				close(waiting)
				<-ctx.Done()
				return false
			},
			func(context.Context) { runs.Add(1) },
		)
		close(done)
	}()

	<-waiting
	cancel()
	<-done

	if got := runs.Load(); got != 1 {
		t.Fatalf("runs after cancellation = %d, want 1", got)
	}
}

func TestDailyCalendarBoundaryHandlesDST(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		now  time.Time
		want time.Duration
	}{
		{
			name: "spring forward",
			now:  time.Date(2026, time.March, 8, 0, 0, 0, 0, location),
			want: 23 * time.Hour,
		},
		{
			name: "fall back",
			now:  time.Date(2026, time.November, 1, 0, 0, 0, 0, location),
			want: 25 * time.Hour,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := untilNextMidnight(test.now, location); got != test.want {
				t.Fatalf("until next midnight = %s, want %s", got, test.want)
			}
		})
	}
}

func TestDailyDoesNotOverlapJobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	done := make(chan struct{})
	var runs atomic.Int64
	var active atomic.Int64
	var maximum atomic.Int64
	var waits atomic.Int64

	go func() {
		daily(ctx, time.Now, time.UTC,
			func(context.Context, time.Duration) bool {
				return waits.Add(1) == 1
			},
			func(context.Context) {
				current := active.Add(1)
				for {
					observed := maximum.Load()
					if current <= observed || maximum.CompareAndSwap(observed, current) {
						break
					}
				}
				invocation := runs.Add(1)
				if invocation == 1 {
					close(firstStarted)
					<-releaseFirst
				}
				active.Add(-1)
			},
		)
		close(done)
	}()

	<-firstStarted
	if got := waits.Load(); got != 0 {
		t.Fatalf("scheduler waited while first job was active: waits = %d", got)
	}
	close(releaseFirst)
	<-done

	if got := runs.Load(); got != 2 {
		t.Fatalf("runs = %d, want 2", got)
	}
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent jobs = %d, want 1", got)
	}
}

func TestDailySkipsJobWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var runs int

	daily(ctx, time.Now, time.UTC, func(context.Context, time.Duration) bool {
		t.Fatal("wait called for cancelled context")
		return false
	}, func(context.Context) {
		runs++
	})

	if runs != 0 {
		t.Fatalf("runs = %d, want 0", runs)
	}
}
