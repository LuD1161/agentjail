package shieldapp

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerClearer wraps a writer and stops the spinner on first write,
// then passes all writes through to the underlying writer directly.
type spinnerClearer struct {
	sp   *spinner
	w    io.Writer
	once sync.Once
}

func (sc *spinnerClearer) Write(p []byte) (int, error) {
	sc.once.Do(func() {
		sc.sp.clear()
	})
	return sc.w.Write(p)
}

type spinner struct {
	mu      sync.Mutex
	msg     string
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	noColor bool
}

func newSpinner() *spinner {
	return &spinner{
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		noColor: os.Getenv("NO_COLOR") != "",
	}
}

func (s *spinner) start(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()

	go func() {
		defer close(s.done)
		i := 0
		for {
			select {
			case <-s.stop:
				// Clear the spinner line
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			default:
				s.mu.Lock()
				m := s.msg
				s.mu.Unlock()

				frame := spinFrames[i%len(spinFrames)]
				if s.noColor {
					fmt.Fprintf(os.Stderr, "\r  %s %s", frame, m)
				} else {
					fmt.Fprintf(os.Stderr, "\r  \033[36m%s\033[0m %s", frame, m)
				}
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

func (s *spinner) update(msg string) {
	s.mu.Lock()
	// Clear previous line in case new message is shorter
	fmt.Fprintf(os.Stderr, "\r\033[K")
	s.msg = msg
	s.mu.Unlock()
}

func (s *spinner) clear() {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

func (s *spinner) succeed(msg string) {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
	if s.noColor {
		fmt.Fprintf(os.Stderr, "  ✓ %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "  \033[32m✓\033[0m %s\n", msg)
	}
}

func (s *spinner) fail(msg string) {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
	if s.noColor {
		fmt.Fprintf(os.Stderr, "  ✗ %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "  \033[31m✗\033[0m %s\n", msg)
	}
}
