// Package bandwidth provides per-proxy bandwidth monitoring and quota management.
//
// Each proxy tracks inbound/outbound bytes in hourly buckets. Configurable
// quotas (hourly, daily, weekly, monthly) can trigger automatic suspension
// when exceeded. The timezone is used for all reset calculations.
package bandwidth

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Quota defines bandwidth limits for different time windows. A value of 0
// means unlimited for that window. All values are in bytes.
type Quota struct {
	Hourly  int64 `yaml:"hourly" json:"hourly"`
	Daily   int64 `yaml:"daily" json:"daily"`
	Weekly  int64 `yaml:"weekly" json:"weekly"`
	Monthly int64 `yaml:"monthly" json:"monthly"`
}

// IsZero reports whether all quotas are zero (unlimited).
func (q Quota) IsZero() bool {
	return q.Hourly == 0 && q.Daily == 0 && q.Weekly == 0 && q.Monthly == 0
}

// Tracker monitors bandwidth usage for one proxy.
type Tracker struct {
	mu sync.RWMutex

	name     string
	quota    Quota
	location *time.Location

	// Hourly buckets: key is unix hour, value is a BytePair
	buckets map[int64]*BytePair

	// Running totals for current windows
	inbound  atomic.Int64
	outbound atomic.Int64

	// Suspension state
	suspended atomic.Bool
	suspendMu sync.Mutex

	// Cleanup ticker
	stop chan struct{}
	once sync.Once
}

// BytePair holds inbound and outbound byte counters.
type BytePair struct {
	In  atomic.Int64
	Out atomic.Int64
}

// Snapshot is a point-in-time reading of bandwidth usage.
type Snapshot struct {
	Name           string `json:"name"`
	Inbound        int64  `json:"inbound_bytes"`
	Outbound       int64  `json:"outbound_bytes"`
	Total          int64  `json:"total_bytes"`
	Suspended      bool   `json:"suspended"`
	Quota          Quota  `json:"quota"`
	HourlyUsed     int64  `json:"hourly_used"`
	DailyUsed      int64  `json:"daily_used"`
	WeeklyUsed     int64  `json:"weekly_used"`
	MonthlyUsed    int64  `json:"monthly_used"`
	HourlyPercent  float64 `json:"hourly_percent"`
	DailyPercent   float64 `json:"daily_percent"`
	WeeklyPercent  float64 `json:"weekly_percent"`
	MonthlyPercent float64 `json:"monthly_percent"`
}

// NewTracker creates a bandwidth tracker for a proxy.
func NewTracker(name string, quota Quota, location *time.Location) *Tracker {
	if location == nil {
		location = time.UTC
	}
	t := &Tracker{
		name:     name,
		quota:    quota,
		location: location,
		buckets:  make(map[int64]*BytePair),
		stop:     make(chan struct{}),
	}
	// Run hourly cleanup
	go t.cleanupLoop()
	return t
}

// RecordIn adds inbound bytes to the tracker.
func (t *Tracker) RecordIn(n int64) {
	t.inbound.Add(n)
	hour := t.currentHour()
	t.mu.Lock()
	bp, ok := t.buckets[hour]
	if !ok {
		bp = &BytePair{}
		t.buckets[hour] = bp
	}
	t.mu.Unlock()
	bp.In.Add(n)
	t.maybeCheckQuota()
}

// RecordOut adds outbound bytes to the tracker.
func (t *Tracker) RecordOut(n int64) {
	t.outbound.Add(n)
	hour := t.currentHour()
	t.mu.Lock()
	bp, ok := t.buckets[hour]
	if !ok {
		bp = &BytePair{}
		t.buckets[hour] = bp
	}
	t.mu.Unlock()
	bp.Out.Add(n)
	t.maybeCheckQuota()
}

// maybeCheckQuota re-evaluates quotas right after bytes are recorded so that
// suspension takes effect promptly. Relying on the hourly cleanup loop alone
// would delay enforcement by up to an hour, letting a proxy blow far past its
// quota. It short-circuits once already suspended to bound the per-packet cost
// on the UDP hot path.
func (t *Tracker) maybeCheckQuota() {
	if t.suspended.Load() {
		return
	}
	t.CheckQuota()
}

// Suspended reports whether the proxy is currently suspended due to quota.
func (t *Tracker) Suspended() bool { return t.suspended.Load() }

// Suspend manually suspends the proxy.
func (t *Tracker) Suspend() { t.suspended.Store(true) }

// Resume manually resumes the proxy.
func (t *Tracker) Resume() { t.suspended.Store(false) }

// SetQuota updates the quota at runtime.
func (t *Tracker) SetQuota(q Quota) {
	t.mu.Lock()
	t.quota = q
	t.mu.Unlock()
}

// QuotaConfig returns the current quota.
func (t *Tracker) QuotaConfig() Quota {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.quota
}

// CheckQuota checks all windows and returns the first exceeded window name,
// or empty string if under quota. If a window is exceeded, the proxy is
// automatically suspended.
func (t *Tracker) CheckQuota() string {
	t.mu.RLock()
	q := t.quota
	t.mu.RUnlock()

	if q.IsZero() {
		return ""
	}

	now := time.Now().In(t.location)
	snap := t.snapshot(now, q)

	// Check hourly
	if q.Hourly > 0 && snap.HourlyUsed >= q.Hourly {
		t.suspended.Store(true)
		return "hourly"
	}
	// Check daily
	if q.Daily > 0 && snap.DailyUsed >= q.Daily {
		t.suspended.Store(true)
		return "daily"
	}
	// Check weekly
	if q.Weekly > 0 && snap.WeeklyUsed >= q.Weekly {
		t.suspended.Store(true)
		return "weekly"
	}
	// Check monthly
	if q.Monthly > 0 && snap.MonthlyUsed >= q.Monthly {
		t.suspended.Store(true)
		return "monthly"
	}

	return ""
}

// Snapshot returns the current bandwidth usage statistics.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.RLock()
	q := t.quota
	t.mu.RUnlock()
	return t.snapshot(time.Now().In(t.location), q)
}

func (t *Tracker) snapshot(now time.Time, q Quota) Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var hourly, daily, weekly, monthly int64

	hourStart := now.Truncate(time.Hour).Unix()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, t.location).Unix()
	weekday := now.Weekday()
	if weekday == time.Sunday {
		weekday = 7
	}
	weekStart := time.Date(now.Year(), now.Month(), now.Day()-int(weekday)+1, 0, 0, 0, 0, t.location).Unix()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, t.location).Unix()

	for hour, bp := range t.buckets {
		total := bp.In.Load() + bp.Out.Load()
		if hour >= hourStart {
			hourly += total
		}
		if hour >= dayStart/3600*3600 {
			daily += total
		}
		if hour >= weekStart/3600*3600 {
			weekly += total
		}
		if hour >= monthStart/3600*3600 {
			monthly += total
		}
	}

	s := Snapshot{
		Name:        t.name,
		Inbound:     t.inbound.Load(),
		Outbound:    t.outbound.Load(),
		Total:       t.inbound.Load() + t.outbound.Load(),
		Suspended:   t.suspended.Load(),
		Quota:       q,
		HourlyUsed:  hourly,
		DailyUsed:   daily,
		WeeklyUsed:  weekly,
		MonthlyUsed: monthly,
	}
	if q.Hourly > 0 {
		s.HourlyPercent = float64(hourly) / float64(q.Hourly) * 100
	}
	if q.Daily > 0 {
		s.DailyPercent = float64(daily) / float64(q.Daily) * 100
	}
	if q.Weekly > 0 {
		s.WeeklyPercent = float64(weekly) / float64(q.Weekly) * 100
	}
	if q.Monthly > 0 {
		s.MonthlyPercent = float64(monthly) / float64(q.Monthly) * 100
	}
	return s
}

// Reset resets all counters to zero. Use with caution — this clears the
// entire bucket history.
func (t *Tracker) Reset() {
	t.mu.Lock()
	t.buckets = make(map[int64]*BytePair)
	t.mu.Unlock()
	t.inbound.Store(0)
	t.outbound.Store(0)
	t.suspended.Store(false)
}

// Close stops the cleanup goroutine.
func (t *Tracker) Close() {
	t.once.Do(func() { close(t.stop) })
}

func (t *Tracker) currentHour() int64 {
	return time.Now().In(t.location).Truncate(time.Hour).Unix()
}

func (t *Tracker) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.pruneOldBuckets()
			t.CheckQuota()
		}
	}
}

func (t *Tracker) pruneOldBuckets() {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Keep last 31 days of hourly buckets
	cutoff := time.Now().Add(-31 * 24 * time.Hour).Unix()
	for hour := range t.buckets {
		if hour < cutoff {
			delete(t.buckets, hour)
		}
	}
}

// UsageStats is a simpler view for the metrics collector.
type UsageStats struct {
	Inbound  int64
	Outbound int64
}

// Stats returns current in/out totals (fast path, no lock).
func (t *Tracker) Stats() UsageStats {
	return UsageStats{
		Inbound:  t.inbound.Load(),
		Outbound: t.outbound.Load(),
	}
}

// FormatBytes returns a human-readable string for byte counts.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
