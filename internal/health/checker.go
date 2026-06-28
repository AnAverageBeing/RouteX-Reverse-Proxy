// Package health implements active TCP health checks against upstream targets.
//
// A Checker runs one probe goroutine per (IP, port) target. On each interval it
// attempts a TCP dial with the configured timeout. Successive failures past
// FailuresBeforeEject mark the target unhealthy; PassesBeforeReadmit
// consecutive successes restore it. State changes are reported to a supplied
// OnChange callback (typically a `*lb.Balancer.SetHealth` adapter) so the
// balancer can immediately skip the target.
//
// The Checker honors a context.Context so the proxy manager can stop all probes
// deterministically during reload/shutdown. Probes never block shutdown — even
// in-flight dials are abandoned via the dial timeout + context cancellation.
package health

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Config holds the per-checker tunables. Values mirror the Phase A
// GlobalDefaults / ProxyHealthCheckOverride contract — zero values are rejected
// at construction; the proxy manager resolves overrides against the global
// defaults before constructing a Checker.
type Config struct {
	Interval                 time.Duration
	Timeout                  time.Duration
	FailuresBeforeEject      int
	PassesBeforeReadmit      int
}

// Target is one upstream the checker probes.
type Target struct {
	IP   net.IP
	Port int
}

// String renders a target as host:port.
func (t Target) String() string {
	if t.IP == nil {
		return "<nil>:0"
	}
	return net.JoinHostPort(t.IP.String(), fmt.Sprintf("%d", t.Port))
}

// HealthCallback is invoked whenever a target's computed healthy state changes.
// The new value is supplied along with the (IP, port) tuple. Implementations
// must be non-blocking — the checker holds its own lock while invoking them.
type HealthCallback func(ip net.IP, port int, healthy bool)

// Checker orchestrates probes for a set of targets.
type Checker struct {
	cfg      Config
	targets  []Target
	onChange HealthCallback
	logger   *zap.Logger

	// state per target index: consecutive failure and success counters.
	mu        sync.Mutex
	fail      []int
	pass      []int
	healthySn []bool // last announced state so we only fire onChange on diffs.

	// running tracks goroutine lifecycle. cancel detaches from caller ctx; wg
	// waits for probe goroutines to fully exit on Stop.
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool
}

// New constructs a Checker. The supplied targets must be non-empty; the
// callback may be nil if the caller intends to poll Healthy() instead.
func New(cfg Config, targets []Target, onChange HealthCallback, logger *zap.Logger) (*Checker, error) {
	if cfg.Interval <= 0 {
		return nil, fmt.Errorf("health: interval must be > 0 (got %s)", cfg.Interval)
	}
	if cfg.Timeout <= 0 || cfg.Timeout > cfg.Interval {
		return nil, fmt.Errorf("health: timeout must be in (0, interval] (got %s, interval %s)", cfg.Timeout, cfg.Interval)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("health: at least one target is required")
	}
	c := &Checker{
		cfg:       cfg,
		targets:   append([]Target(nil), targets...),
		onChange:   onChange,
		logger:     logger,
		fail:       make([]int, len(targets)),
		pass:       make([]int, len(targets)),
		healthySn:  make([]bool, len(targets)),
	}
	for i := range c.healthySn {
		c.healthySn[i] = true
	}
	return c, nil
}

// Start spins up one probe goroutine per target. Idempotent: a second Start is
// a no-op. The supplied parent context bounds all probe goroutines; cancelling
// it (or calling Stop) tears them down within `cfg.Timeout + cfg.Interval`.
func (c *Checker) Start(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	for i := range c.targets {
		i := i
		c.wg.Add(1)
		go c.loop(ctx, i)
	}
	return nil
}

// Stop signals all probe goroutines to exit and waits for them to drain.
// Idempotent. Safe to call concurrently.
func (c *Checker) Stop() {
	if !c.running.CompareAndSwap(true, false) {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

// Healthy reports the last announced health state for the (ip, port) tuple.
// When probes have never completed, returns true (optimistic) so freshly
// started checkers don't immediately eject all upstreams.
func (c *Checker) Healthy(ip net.IP, port int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, t := range c.targets {
		if t.IP.Equal(ip) && t.Port == port {
			return c.healthySn[i]
		}
	}
	return true
}

// loop runs the probe cycle for one target. It exits cleanly when ctx is
// cancelled.
func (c *Checker) loop(ctx context.Context, idx int) {
	defer c.wg.Done()
	// Stagger start so a checker with many targets doesn't synchronously dial
	// them all at once at the first tick. Spacing: interval / N, capped at one
	// full interval so we never push probes into the next tick window.
	n := len(c.targets)
	if n < 1 {
		n = 1
	}
	stagger := time.Duration(idx) * (c.cfg.Interval / time.Duration(n))
	if stagger >= c.cfg.Interval {
		stagger = 0
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(stagger):
	}
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	c.probeOnce(ctx, idx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.probeOnce(ctx, idx)
		}
	}
}

// probeOnce dials the target and updates the per-target counters, firing
// onChange only when the computed healthy state transitions.
func (c *Checker) probeOnce(ctx context.Context, idx int) {
	t := c.targets[idx]
	addr := t.String()
	dialer := net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
	}
	healthy := err == nil

	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.healthySn[idx]
	if healthy {
		c.pass[idx]++
		c.fail[idx] = 0
		// Readmit only after enough consecutive passes.
		if !prev {
			if c.pass[idx] >= c.cfg.PassesBeforeReadmit {
				c.healthySn[idx] = true
			}
		}
	} else {
		c.fail[idx]++
		c.pass[idx] = 0
		if prev {
			if c.fail[idx] >= c.cfg.FailuresBeforeEject {
				c.healthySn[idx] = false
			}
		}
	}
	after := c.healthySn[idx]
	if after != prev {
		if c.logger != nil {
			if after {
				c.logger.Info("health: upstream readmitted",
					zap.String("upstream", addr),
					zap.Int("passes", c.pass[idx]))
			} else {
				c.logger.Warn("health: upstream ejected",
					zap.String("upstream", addr),
					zap.Int("failures", c.fail[idx]))
			}
		}
		if c.onChange != nil {
			c.onChange(t.IP, t.Port, after)
		}
	}
}

