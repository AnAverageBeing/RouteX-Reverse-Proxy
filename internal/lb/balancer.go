// Package lb implements upstream selection for the proxy layer.
//
// A Balancer holds the set of candidate upstream (IP, port) targets produced by
// combining destination IPs with destination ports. Each algorithm below picks
// one target per Pick call while honouring health state and (optionally) source
// affinity.
//
// Lifecycle: the proxy layer creates one Balancer per (origin port) listener.
// The balancer is goroutine-safe — concurrent Accept loops on the same listener
// may call Pick simultaneously.
package lb

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Target is a single upstream candidate. Weight is honoured only by the
// "weighted" algorithm; other algorithms ignore it. Healthy tracks the live
// health-check result — the picker skips unhealthy targets when at least one
// healthy target remains.
type Target struct {
	IP     net.IP
	Port   int
	Weight int

	// healthy is read/written atomically: 1 = healthy, 0 = unhealthy. Stored as
	// int32 so callers may use atomic operations withoutRace-tested shims.
	healthy int32

	// activeConns is incremented at Pick and decremented at Release. Algos that
	// consult load (least-conn) read this counter; others leave it alone but keep
	// it updated so /api/proxies/{name}/upstreams can render live counts.
	activeConns int64
	// totalConns is a monotonically increasing counter of all-conns-ever picked
	// to this target. Used by the metrics subsystem.
	totalConns int64
	// failCount counts consecutive health probe failures from the checker.
	failCount int64
}

// String renders the target in host:port form.
func (t *Target) String() string {
	if t == nil || t.IP == nil {
		return "<nil-upstream>"
	}
	return net.JoinHostPort(t.IP.String(), fmt.Sprintf("%d", t.Port))
}

// HealthMark atomically sets the healthy flag and returns the previous value.
func (t *Target) HealthMark(healthy bool) bool {
	var v int32 = 0
	if healthy {
		v = 1
	}
	return atomic.SwapInt32(&t.healthy, v) == 1
}

// IsHealthy loads the health flag atomically.
func (t *Target) IsHealthy() bool { return atomic.LoadInt32(&t.healthy) == 1 }

// IncActive atomically increments active-conns and total-conns.
func (t *Target) IncActive() {
	atomic.AddInt64(&t.activeConns, 1)
	atomic.AddInt64(&t.totalConns, 1)
}

// DecActive atomically decrements active-conns (clamped at zero).
func (t *Target) DecActive() {
	v := atomic.AddInt64(&t.activeConns, -1)
	if v < 0 {
		// Restore to zero if an over-release happened.
		atomic.AddInt64(&t.activeConns, -v)
	}
}

// ActiveConns returns the live active count.
func (t *Target) ActiveConns() int64 { return atomic.LoadInt64(&t.activeConns) }

// TotalConns returns the cumulative picked count.
func (t *Target) TotalConns() int64 { return atomic.LoadInt64(&t.totalConns) }

// IncFail atomically increments the consecutive failure count.
func (t *Target) IncFail() int64 { return atomic.AddInt64(&t.failCount, 1) }

// ResetFail atomically zeroes the failure count after a successful probe.
func (t *Target) ResetFail() { atomic.StoreInt64(&t.failCount, 0) }

// FailCount returns the current consecutive failure count.
func (t *Target) FailCount() int64 { return atomic.LoadInt64(&t.failCount) }

// Algorithm enumerates the supported upstream selection strategies. The string
// values match the YAML config directly so config-driven construction does not
// need a translation layer.
type Algorithm string //nolint:recvcheck // intentional; Algorithm is a config string union

const (
	// AlgRoundRobin selects targets in rotating order, skipping unhealthy ones.
	AlgRoundRobin Algorithm = "round-robin"
	// AlgLeastConn selects the target with the fewest active conns; ties resolve
	// to the first healthy target encountered.
	AlgLeastConn Algorithm = "least-conn"
	// AlgIPHash hashes srcIP and maps onto the target index — sticky by source.
	AlgIPHash Algorithm = "ip-hash"
	// AlgWeighted selects targets with probability proportional to Weight.
	AlgWeighted Algorithm = "weighted"
	// AlgRandom picks a uniformly random healthy target.
	AlgRandom Algorithm = "random"
)

// Balancer is the upstream-selection façade. Constructed once per (origin port)
// listener; concurrent Pick/Release calls are safe.
type Balancer struct {
	algorithm Algorithm
	targets   []*Target

	// rrCursor is the round-robin cursor — incremented atomically modulo the
	// healthy target count to avoid skew.
	rrCursor uint64

	// rw guards structural changes (target list rebuild on reload). Hot-path
	// reads lock only RLock.
	rw sync.RWMutex

	// stickySessions tracks srcIP → target index for sticky_ttl-bound affinity.
	// Used only when sticky enabled; nil otherwise.
	sticky *stickyTable

	// rng source guarded by rngMu — used by random/weighted algorithms.
	rng   *rand.Rand
	rngMu sync.Mutex
}

// stickyEntry is one sticky-session mapping.
type stickyEntry struct {
	targetIdx int
	expiry    int64 // unix nano
}

// stickyTable holds source-IP → target mappings with TTL expiry.
type stickyTable struct {
	mu  sync.RWMutex
	ttl int64 // nanoseconds
	m   map[string]stickyEntry
}

func newStickyTable(ttlSeconds int) *stickyTable {
	if ttlSeconds <= 0 {
		ttlSeconds = 3600
	}
	return &stickyTable{
		ttl: int64(ttlSeconds) * int64(1e9),
		m:   make(map[string]stickyEntry),
	}
}

// get returns the cached target index for the key, or -1 if absent/expired.
func (s *stickyTable) get(key string, now int64) int {
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	if !ok {
		return -1
	}
	if e.expiry <= now {
		return -1
	}
	return e.targetIdx
}

// put records a sticky mapping with the configured TTL.
func (s *stickyTable) put(key string, idx int, now int64) {
	s.mu.Lock()
	s.m[key] = stickyEntry{targetIdx: idx, expiry: now + s.ttl}
	s.mu.Unlock()
}

// drop removes a sticky mapping if present.
func (s *stickyTable) drop(key string) {
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// len returns the current size of the sticky table.
func (s *stickyTable) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// ErrNoHealthyTargets is returned by Pick when every target is unhealthy.
var ErrNoHealthyTargets = errors.New("lb: no healthy upstream targets available")

// New constructs a Balancer for the supplied algorithm and target list. The
// supplied targets' healthy flag defaults to true; the health checker updates
// it asynchronously. Weights are honoured only by AlgWeighted.
//
// All targets are assumed to be non-nil and to carry valid IPs — the proxy
// manager validates this before construction.
func New(algorithm string, targets []*Target, sticky bool, stickyTTL int) (*Balancer, error) {
	if len(targets) == 0 {
		return nil, errors.New("lb: at least one target is required")
	}
	alg := Algorithm(algorithm)
	switch alg {
	case AlgRoundRobin, AlgLeastConn, AlgIPHash, AlgWeighted, AlgRandom:
	default:
		return nil, fmt.Errorf("lb: unsupported algorithm %q", algorithm)
	}
	b := &Balancer{
		algorithm: alg,
		targets:   make([]*Target, 0, len(targets)),
		rng:       rand.New(rand.NewSource(rand.Int63())),
	}
	for i := range targets {
		t := targets[i]
		if t == nil || t.IP == nil {
			return nil, fmt.Errorf("lb: target[%d] is nil or has nil IP", i)
		}
		// Seed healthy to true unless the caller pre-marked unhealthy.
		if atomic.LoadInt32(&t.healthy) == 0 {
			atomic.StoreInt32(&t.healthy, 1)
		}
		b.targets = append(b.targets, t)
	}
	if sticky {
		b.sticky = newStickyTable(stickyTTL)
	}
	return b, nil
}

// Targets returns a defensive copy of the target slice. Callers must NOT mutate
// the returned slice; the underlying Target pointers are shared for stat reads.
func (b *Balancer) Targets() []*Target {
	b.rw.RLock()
	defer b.rw.RUnlock()
	out := make([]*Target, len(b.targets))
	copy(out, b.targets)
	return out
}

// Pick selects a healthy target for the supplied source IP. Returns
// ErrNoHealthyTargets when every candidate is down. The returned Target pointer
// is shared with the balancer's internal slice — callers MUST call Release when
// the connection challenging completes.
func (b *Balancer) Pick(srcIP net.IP) (*Target, error) {
	b.rw.RLock()
	defer b.rw.RUnlock()

	// Sticky fast-path: if sticky enabled and the source IP has a live mapping,
	// return that target — but only if still healthy.
	if b.sticky != nil && srcIP != nil {
		key := srcIP.String()
		now := nowNanos()
		if idx := b.sticky.get(key, now); idx >= 0 && idx < len(b.targets) && b.targets[idx].IsHealthy() {
			t := b.targets[idx]
			t.IncActive()
			return t, nil
		}
	}

	t, idx, err := b.pickAlg(srcIP)
	if err != nil {
		return nil, err
	}
	t.IncActive()

	if b.sticky != nil && srcIP != nil {
		b.sticky.put(srcIP.String(), idx, nowNanos())
	}
	return t, nil
}

// pickAlg runs the algorithm, scanning healthy targets. Returns the chosen
// target and its index in b.targets.
func (b *Balancer) pickAlg(srcIP net.IP) (*Target, int, error) {
	switch b.algorithm {
	case AlgRoundRobin:
		return b.pickRoundRobin()
	case AlgLeastConn:
		return b.pickLeastConn()
	case AlgIPHash:
		return b.pickIPHash(srcIP)
	case AlgWeighted:
		return b.pickWeighted()
	case AlgRandom:
		return b.pickRandom()
	}
	return nil, 0, fmt.Errorf("lb: unreachable algorithm %q", b.algorithm)
}

// Release decrements the active-conn counter for a target previously returned
// by Pick. Safe to call multiple times; the counter clamps at zero.
func (b *Balancer) Release(t *Target) {
	if t == nil {
		return
	}
	t.DecActive()
}

// SetHealth atomically marks a target healthy or unhealthy. Used by the health
// checker. Targets are matched by (IP, port) — dot equality on net.IP via
// net.IP.Equal.
func (b *Balancer) SetHealth(ip net.IP, port int, healthy bool) {
	b.rw.RLock()
	defer b.rw.RUnlock()
	for _, t := range b.targets {
		if t.IP.Equal(ip) && t.Port == port {
			t.HealthMark(healthy)
			return
		}
	}
}

// MarkAllHealthy sets every target to healthy. Used at startup before the
// first probe completes.
func (b *Balancer) MarkAllHealthy() {
	b.rw.RLock()
	defer b.rw.RUnlock()
	for _, t := range b.targets {
		atomic.StoreInt32(&t.healthy, 1)
		t.ResetFail()
	}
}

// StickySize returns the number of live sticky-session entries, or 0 when
// sticky sessions are disabled.
func (b *Balancer) StickySize() int {
	if b.sticky == nil {
		return 0
	}
	return b.sticky.len()
}

// ─── Algorithms ──────────────────────────────────────────────────────────

// pickRoundRobin rotates the cursor atomically and skips unhealthy targets.
func (b *Balancer) pickRoundRobin() (*Target, int, error) {
	n := len(b.targets)
	start := int(atomic.AddUint64(&b.rrCursor, 1)-1) % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if b.targets[idx].IsHealthy() {
			return b.targets[idx], idx, nil
		}
	}
	return nil, 0, ErrNoHealthyTargets
}

// pickLeastConn selects the healthy target with the fewest active conns.
func (b *Balancer) pickLeastConn() (*Target, int, error) {
	var best *Target
	bestIdx := -1
	var bestConns int64 = -1
	for i, t := range b.targets {
		if !t.IsHealthy() {
			continue
		}
		c := t.ActiveConns()
		if bestIdx == -1 || c < bestConns {
			best = t
			bestIdx = i
			bestConns = c
		}
	}
	if bestIdx == -1 {
		return nil, 0, ErrNoHealthyTargets
	}
	return best, bestIdx, nil
}

// pickIPHash maps srcIP to a stable target index via FNV-32 and skips unhealthy.
// On collision it walks forward looking for the next healthy target.
func (b *Balancer) pickIPHash(srcIP net.IP) (*Target, int, error) {
	if srcIP == nil {
		// No source IP available — fall back to round-robin for fairness.
		return b.pickRoundRobin()
	}
	h := fnv.New32a()
	_, _ = h.Write(srcIP)
	seed := int(h.Sum32()) % len(b.targets)
	if seed < 0 {
		seed = -seed
	}
	for i := 0; i < len(b.targets); i++ {
		idx := (seed + i) % len(b.targets)
		if b.targets[idx].IsHealthy() {
			return b.targets[idx], idx, nil
		}
	}
	return nil, 0, ErrNoHealthyTargets
}

// pickWeighted draws a healthy target weighted by Weight using a cumulative
// distribution. Falls back to round-robin among healthy targets when the sum
// of weights is zero (misconfiguration treated as uniform).
func (b *Balancer) pickWeighted() (*Target, int, error) {
	var healthyIdxs []int
	totalWeight := 0
	for i, t := range b.targets {
		if t.IsHealthy() && t.Weight > 0 {
			healthyIdxs = append(healthyIdxs, i)
			totalWeight += t.Weight
		}
	}
	if len(healthyIdxs) == 0 {
		return nil, 0, ErrNoHealthyTargets
	}
	if totalWeight == 0 {
		// Uniform fallback.
		b.rngMu.Lock()
		pick := b.rng.Intn(len(healthyIdxs))
		b.rngMu.Unlock()
		idx := healthyIdxs[pick]
		return b.targets[idx], idx, nil
	}

	b.rngMu.Lock()
	r := b.rng.Intn(totalWeight)
	b.rngMu.Unlock()
	for _, idx := range healthyIdxs {
		r -= b.targets[idx].Weight
		if r < 0 {
			return b.targets[idx], idx, nil
		}
	}
	// Numeric safety net.
	idx := healthyIdxs[0]
	return b.targets[idx], idx, nil
}

// pickRandom uniformly samples a healthy target.
func (b *Balancer) pickRandom() (*Target, int, error) {
	var healthyIdxs []int
	for i, t := range b.targets {
		if t.IsHealthy() {
			healthyIdxs = append(healthyIdxs, i)
		}
	}
	if len(healthyIdxs) == 0 {
		return nil, 0, ErrNoHealthyTargets
	}
	b.rngMu.Lock()
	pick := b.rng.Intn(len(healthyIdxs))
	b.rngMu.Unlock()
	idx := healthyIdxs[pick]
	return b.targets[idx], idx, nil
}

// nowNanos returns the current time as unix nanoseconds. Wrapped so tests can
// substitute a fake clock if needed via build-tag shims (not currently used).
func nowNanos() int64 { return time.Now().UnixNano() }