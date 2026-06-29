package l7

import (
	"sync"
	"time"
)

type TokenBucket struct {
	rate       float64
	burst      float64
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucket(rate, burst float64) *TokenBucket {
	if burst <= 0 {
		burst = rate
	}
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

func (tb *TokenBucket) AllowOne() bool { return tb.Allow(1) }

// IsFull reports whether the bucket is at or near capacity (>= 99%).
// Used by the engine cleanup loop to prune idle token buckets.
func (tb *TokenBucket) IsFull() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens >= tb.burst*0.99
}

func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}
	tb.lastRefill = now
}

type SlidingWindow struct {
	window     time.Duration
	buckets    []int64
	resolution time.Duration
	numBuckets int
	head       int
	lastTick   time.Time
	mu         sync.Mutex
}

func NewSlidingWindow(window time.Duration, numBuckets int) *SlidingWindow {
	if numBuckets < 1 {
		numBuckets = 10
	}
	return &SlidingWindow{
		window:     window,
		buckets:    make([]int64, numBuckets),
		resolution: window / time.Duration(numBuckets),
		numBuckets: numBuckets,
		lastTick:   time.Now(),
	}
}

func (sw *SlidingWindow) Add(n int64) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.advance()
	sw.buckets[sw.head] += n
}

func (sw *SlidingWindow) Count() int64 {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.advance()
	var total int64
	for _, b := range sw.buckets {
		total += b
	}
	return total
}

func (sw *SlidingWindow) advance() {
	now := time.Now()
	elapsed := now.Sub(sw.lastTick)
	ticks := int(elapsed / sw.resolution)
	if ticks > sw.numBuckets {
		ticks = sw.numBuckets
	}
	for i := 0; i < ticks; i++ {
		sw.head = (sw.head + 1) % sw.numBuckets
		sw.buckets[sw.head] = 0
	}
	if ticks > 0 {
		sw.lastTick = now
	}
}
