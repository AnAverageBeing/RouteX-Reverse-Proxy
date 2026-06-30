package l7

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
)

type Engine struct {
	cfg       config.ProxyL7Protection
	inspector *Inspector

	ipBytesTokens   map[string]*TokenBucket
	ipBytesTokensMu sync.Mutex

	cyclingWindows   map[string]*SlidingWindow
	cyclingWindowsMu sync.Mutex

	scores   map[string]int
	scoresMu sync.Mutex

	bans *banStore

	blockedConns int64
	bannedIPs    int64
	events       []Event
	eventsMu     sync.Mutex

	// FIX #9: cleanup goroutine to prune expired entries from in-memory maps
	stopCleanup chan struct{}
}

type Event struct {
	Time      time.Time `json:"time"`
	IP        net.IP    `json:"ip"`
	EventType string    `json:"event_type"`
	Score     int       `json:"score"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
}

func NewEngine(cfg config.ProxyL7Protection) *Engine {
	e := &Engine{
		cfg:            cfg,
		inspector:      NewInspector(cfg),
		ipBytesTokens:  make(map[string]*TokenBucket),
		cyclingWindows: make(map[string]*SlidingWindow),
		scores:         make(map[string]int),
		bans:           newBanStore(),
		stopCleanup:    make(chan struct{}),
	}
	// FIX #9: start periodic cleanup to prevent unbounded map growth
	go e.cleanupLoop()
	return e
}

// Stop shuts down the background cleanup goroutine.
func (e *Engine) Stop() {
	select {
	case <-e.stopCleanup:
		// already closed
	default:
		close(e.stopCleanup)
	}
}

// FIX #9: cleanupLoop periodically prunes IPs that have been inactive.
// Without this, every unique source IP creates permanent map entries.
func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCleanup:
			return
		case <-ticker.C:
			e.pruneInactiveMaps()
		}
	}
}

func (e *Engine) pruneInactiveMaps() {
	// Prune cyclingWindows for IPs with zero count in their window
	e.cyclingWindowsMu.Lock()
	for key, sw := range e.cyclingWindows {
		if sw.Count() == 0 {
			delete(e.cyclingWindows, key)
		}
	}
	e.cyclingWindowsMu.Unlock()

	// Prune ipBytesTokens that are full (unused IPs refill to burst)
	e.ipBytesTokensMu.Lock()
	for key, tb := range e.ipBytesTokens {
		if tb.IsFull() {
			delete(e.ipBytesTokens, key)
		}
	}
	e.ipBytesTokensMu.Unlock()

	// Prune zero scores
	e.scoresMu.Lock()
	for key, score := range e.scores {
		if score <= 0 {
			delete(e.scores, key)
		}
	}
	e.scoresMu.Unlock()
}

func (e *Engine) OnAccept(srcIP net.IP) bool {
	if !e.cfg.Enabled || srcIP == nil {
		return true
	}
	if e.bans.IsBanned(srcIP) {
		atomic.AddInt64(&e.blockedConns, 1)
		return false
	}
	if e.cfg.ConnectionCycling.Enabled {
		key := srcIP.String()
		e.cyclingWindowsMu.Lock()
		sw, ok := e.cyclingWindows[key]
		if !ok {
			sw = NewSlidingWindow(time.Duration(e.cfg.ConnectionCycling.Window), 10)
			e.cyclingWindows[key] = sw
		}
		sw.Add(1)
		count := sw.Count()
		e.cyclingWindowsMu.Unlock()
		if count > int64(e.cfg.ConnectionCycling.MaxConnsInWindow) {
			e.addEvent(srcIP, "connection_cycling", e.getRuleScore("connection_cycling"), "blocked",
				"too many connections in window")
			e.addScore(srcIP, e.getRuleScore("connection_cycling"))
			atomic.AddInt64(&e.blockedConns, 1)
			return false
		}
	}
	return true
}

// NeedsFirstPayload reports whether this engine must see the first client
// payload to do its job (protocol inspection or per-IP payload rate limiting).
// When false, the proxy can skip the blocking first-read and avoid stalling
// server-speaks-first protocols that have L7 enabled only for accept-time gating
// (bans / connection cycling).
func (e *Engine) NeedsFirstPayload() bool {
	if !e.cfg.Enabled {
		return false
	}
	return e.cfg.PayloadInspection.Enabled || e.cfg.PayloadRateLimit.Enabled
}

func (e *Engine) OnData(srcIP net.IP, payload []byte, inspected *bool) bool {
	if !e.cfg.Enabled || srcIP == nil {
		return true
	}
	if !*inspected {
		*inspected = true
		if !e.inspector.Inspect(payload) {
			e.addEvent(srcIP, "invalid_protocol", e.getRuleScore("invalid_protocol"), "blocked",
				"payload failed protocol inspection")
			e.addScore(srcIP, e.getRuleScore("invalid_protocol"))
			atomic.AddInt64(&e.blockedConns, 1)
			return false
		}
	}
	if e.cfg.PayloadRateLimit.Enabled {
		if e.cfg.PayloadRateLimit.MaxBytesPerSecPerIP > 0 {
			key := srcIP.String()
			e.ipBytesTokensMu.Lock()
			tb, ok := e.ipBytesTokens[key]
			if !ok {
				rate := float64(e.cfg.PayloadRateLimit.MaxBytesPerSecPerIP)
				burst := rate * e.cfg.PayloadRateLimit.BurstMultiplier
				if burst <= 0 {
					burst = rate * 2
				}
				tb = NewTokenBucket(rate, burst)
				e.ipBytesTokens[key] = tb
			}
			allowed := tb.Allow(float64(len(payload)))
			e.ipBytesTokensMu.Unlock()
			if !allowed {
				e.addEvent(srcIP, "payload_rate_exceeded", e.getRuleScore("payload_rate_exceeded"), "blocked",
					"IP payload rate limit exceeded")
				e.addScore(srcIP, e.getRuleScore("payload_rate_exceeded"))
				atomic.AddInt64(&e.blockedConns, 1)
				return false
			}
		}
	}
	return true
}

func (e *Engine) addScore(ip net.IP, points int) {
	if points <= 0 || !e.cfg.BehavioralScoring.Enabled {
		return
	}
	e.scoresMu.Lock()
	e.scores[ip.String()] += points
	current := e.scores[ip.String()]
	e.scoresMu.Unlock()
	if current >= e.cfg.BehavioralScoring.BanThreshold {
		banDur := time.Duration(e.cfg.BehavioralScoring.BanDuration)
		expires := time.Now().Add(banDur).UnixNano()
		e.bans.Ban(ip, expires, "behavioral threshold exceeded")
		atomic.AddInt64(&e.bannedIPs, 1)
		e.addEvent(ip, "banned", 0, "banned", "behavioral score threshold reached")
		e.scoresMu.Lock()
		delete(e.scores, ip.String())
		e.scoresMu.Unlock()
	}
}

func (e *Engine) getRuleScore(eventType string) int {
	for _, rule := range e.cfg.BehavioralScoring.ScoreRules {
		if rule.Event == eventType {
			return rule.Score
		}
	}
	switch eventType {
	case "payload_too_small":
		return 5
	case "payload_too_large":
		return 10
	case "handshake_timeout":
		return 20
	case "invalid_protocol":
		return 30
	case "connection_cycling":
		return 25
	case "amplification_detected":
		return 40
	}
	return 0
}

func (e *Engine) addEvent(ip net.IP, typ string, score int, action, reason string) {
	e.eventsMu.Lock()
	e.events = append(e.events, Event{
		Time: time.Now(), IP: ip, EventType: typ,
		Score: score, Action: action, Reason: reason,
	})
	if len(e.events) > 1000 {
		e.events = e.events[len(e.events)-1000:]
	}
	e.eventsMu.Unlock()
}

func (e *Engine) BlockedConns() int64     { return atomic.LoadInt64(&e.blockedConns) }
func (e *Engine) BannedIPs() int64        { return int64(e.bans.Count()) }
func (e *Engine) IsBanned(ip net.IP) bool { return e.bans.IsBanned(ip) }

func (e *Engine) BanIP(ip net.IP, duration time.Duration, reason string) {
	expires := int64(0)
	if duration > 0 {
		expires = time.Now().Add(duration).UnixNano()
	}
	e.bans.Ban(ip, expires, reason)
	atomic.AddInt64(&e.bannedIPs, 1)
}

func (e *Engine) UnbanIP(ip net.IP)      { e.bans.Unban(ip) }
func (e *Engine) BannedList() []banEntry { return e.bans.List() }

func (e *Engine) Events(limit int) []Event {
	e.eventsMu.Lock()
	defer e.eventsMu.Unlock()
	if limit <= 0 || limit > len(e.events) {
		limit = len(e.events)
	}
	out := make([]Event, limit)
	copy(out, e.events[len(e.events)-limit:])
	return out
}
