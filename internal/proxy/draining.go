package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Drainer coordinates graceful shutdown of in-flight connections when a proxy
// instance is being stopped or reloaded. New connections are rejected by the
// listener closing; existing connections run until they hit EOF or the
// configured drain timeout elapses, whichever comes first.
//
// Implementation: the proxy loop registers each copy-goroutine pair via Track,
// which adds one to an internal WaitGroup. The loop calls the returned `done`
// callback when its goroutine completes. Wait blocks on the WG but bounded by
// the drain deadline — a hung connection never blocks shutdown indefinitely.
type Drainer struct {
	wg      sync.WaitGroup
	timeout time.Duration
	logger  *zap.Logger
	live    int64 // tracked atomically for introspection
	closing uint32 // 1 once shutdown started (debug only)
}

// NewDrainer constructs a Drainer with the supplied timeout. A zero timeout
// means "no waiting" — Wait returns immediately.
func NewDrainer(timeout time.Duration, logger *zap.Logger) *Drainer {
	return &Drainer{timeout: timeout, logger: logger}
}

// Track records the start of a new copy goroutine/pair. Callers must invoke the
// returned done callback exactly once when the goroutine completes.
func (d *Drainer) Track() (done func()) {
	d.wg.Add(1)
	atomic.AddInt64(&d.live, 1)
	return func() {
		atomic.AddInt64(&d.live, -1)
		d.wg.Done()
	}
}

// Wait blocks until all tracked goroutines have called their done callback, the
// drain timeout elapses, or ctx is cancelled — whichever comes first.
// Subsequent calls are no-ops so the manager may safely call it twice.
func (d *Drainer) Wait(ctx context.Context) {
	if !atomic.CompareAndSwapUint32(&d.closing, 0, 1) {
		return
	}
	if d.timeout <= 0 {
		return
	}
	waited := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(d.timeout):
		if d.logger != nil {
			d.logger.Warn("proxy: drain timeout exceeded, abandoning live conns",
				zap.Int64("live_remaining", atomic.LoadInt64(&d.live)))
		}
	case <-ctx.Done():
	}
}

// Live returns the currently-draining goroutine count.
func (d *Drainer) Live() int64 { return atomic.LoadInt64(&d.live) }