package server

import (
	"context"
	"sync/atomic"
	"time"
)

// lifecycle tracks client liveness so the binary can exit when the browser
// tab is closed (close-beacon) or the user wanders off (heartbeat stale).
type lifecycle struct {
	idleTimeout time.Duration
	lastBeatNS  atomic.Int64 // unix nanos of last heartbeat
	closed      atomic.Bool  // explicit close-beacon received
}

func newLifecycle(idle time.Duration) *lifecycle {
	return &lifecycle{idleTimeout: idle}
}

func (l *lifecycle) beat() {
	l.lastBeatNS.Store(time.Now().UnixNano())
}

func (l *lifecycle) close() {
	l.closed.Store(true)
}

// watch runs until ctx is cancelled or a shutdown trigger fires, at which
// point it invokes onShutdown exactly once.
func (l *lifecycle) watch(ctx context.Context, onShutdown func()) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if l.closed.Load() {
				onShutdown()
				return
			}
			last := time.Unix(0, l.lastBeatNS.Load())
			if time.Since(last) > l.idleTimeout {
				onShutdown()
				return
			}
		}
	}
}
