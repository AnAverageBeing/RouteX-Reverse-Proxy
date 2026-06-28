package l7_test

import (
	"sync"
	"testing"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/l7"
)

func TestTokenBucket_Basic(t *testing.T) {
	tb := l7.NewTokenBucket(100, 100)
	if !tb.AllowOne() {
		t.Error("initial token should be allowed")
	}
	// Consume 99 more
	for i := 0; i < 99; i++ {
		if !tb.AllowOne() {
			t.Errorf("token %d should be allowed", i+2)
		}
	}
	// Bucket should be empty now
	if tb.AllowOne() {
		t.Error("should reject when bucket is empty")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	tb := l7.NewTokenBucket(500, 500)
	// Drain
	for i := 0; i < 500; i++ {
		tb.AllowOne()
	}
	if tb.AllowOne() {
		t.Error("should be empty after draining")
	}
	// Wait for refill
	time.Sleep(100 * time.Millisecond)
	if !tb.AllowOne() {
		t.Error("should allow after refill (~50 tokens in 100ms at 500/sec)")
	}
}

func TestTokenBucket_Burst(t *testing.T) {
	tb := l7.NewTokenBucket(10, 50)
	// Should be able to consume burst amount immediately
	for i := 0; i < 50; i++ {
		if !tb.AllowOne() {
			t.Errorf("burst token %d should be allowed", i+1)
		}
	}
	// Bucket should be empty now
	if tb.AllowOne() {
		t.Error("should reject after burst exhausted")
	}
}

func TestTokenBucket_Concurrent(t *testing.T) {
	tb := l7.NewTokenBucket(10000, 10000)
	var wg sync.WaitGroup
	allowed := make(chan bool, 1000)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				allowed <- tb.AllowOne()
			}
		}()
	}
	wg.Wait()
	close(allowed)
	passed := 0
	for ok := range allowed {
		if ok {
			passed++
		}
	}
	if passed < 900 {
		t.Errorf("concurrent allows = %d, expected >= 900 (10000 burst)", passed)
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	tb := l7.NewTokenBucket(1000, 5000)
	if !tb.Allow(1000) {
		t.Error("should allow 1000 bytes at once")
	}
	if tb.Allow(5000) {
		t.Error("should reject 5000 when only ~4000 tokens remain")
	}
}

func TestSlidingWindow_Basic(t *testing.T) {
	sw := l7.NewSlidingWindow(10*time.Second, 10)
	if sw.Count() != 0 {
		t.Error("initial count should be 0")
	}
	sw.Add(5)
	sw.Add(3)
	if sw.Count() != 8 {
		t.Errorf("count = %d, want 8", sw.Count())
	}
}

func TestSlidingWindow_WindowExpiry(t *testing.T) {
	sw := l7.NewSlidingWindow(200*time.Millisecond, 10)
	sw.Add(100)
	if sw.Count() != 100 {
		t.Errorf("count = %d, want 100", sw.Count())
	}
	// Wait for window to expire
	time.Sleep(300 * time.Millisecond)
	after := sw.Count()
	if after > 50 {
		t.Errorf("count after window expiry = %d, should be mostly expired", after)
	}
}

func TestSlidingWindow_Concurrent(t *testing.T) {
	sw := l7.NewSlidingWindow(10*time.Second, 10)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				sw.Add(1)
			}
		}()
	}
	wg.Wait()
	if sw.Count() != 1000 {
		t.Errorf("concurrent count = %d, want 1000", sw.Count())
	}
}
