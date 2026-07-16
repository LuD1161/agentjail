package daemonapp

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

// A cancelled ctx must end the drain loop, never abort a write already
// dequeued — drainDecisions promises shutdown flushes pending writes.
//
// The loss is racy by nature (select picks randomly among ready cases), so
// this runs enough trials that a regression is not a coin flip: each trial
// loses ~1 record unfixed, making a clean 20-trial run overwhelmingly
// unlikely.
func TestDrainDecisionsShutdownPersistsBufferedRecords(t *testing.T) {
	const (
		trials   = 20
		perTrial = 50
	)

	for i := 0; i < trials; i++ {
		st, err := store.Open(filepath.Join(t.TempDir(), "drain.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}

		s := &server{eventStore: st, decCh: make(chan store.DecisionRecord, 1024)}
		for j := 0; j < perTrial; j++ {
			s.enqueueDecision(store.DecisionRecord{
				Ts:        time.Now(),
				SessionID: "shutdown",
				Agent:     "claude-code",
				ToolName:  "Bash",
				Action:    "allow",
			})
		}

		// Cancel first, then drain: both select cases are ready, which is
		// exactly the shutdown race.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s.decWg.Add(1)
		go s.drainDecisions(ctx)
		s.decWg.Wait()

		got, err := st.DecisionCount(context.Background())
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		// Not decDropped: the shutdown flush already swapped it into a
		// decisions.dropped event, so it reads 0 here either way.
		if got != perTrial {
			t.Fatalf("trial %d: persisted %d of %d buffered records — shutdown lost %d",
				i, got, perTrial, perTrial-got)
		}
		_ = st.Close()
	}
}
