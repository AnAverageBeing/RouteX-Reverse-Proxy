package l7

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
)

type CustomRule struct {
	Name        string
	MatchOffset int
	MatchBytes  []byte
	Action      string
}

type Inspector struct {
	mu          sync.RWMutex
	detector    *ProtocolDetector
	customRules []CustomRule
	enabled     bool
	mode        string
	// FIX #7: use atomic counters — previously these were plain int64 mutated
	// while holding only RLock, causing a data race under concurrent inspection.
	passed  atomic.Int64
	dropped atomic.Int64
}

func NewInspector(l7c config.ProxyL7Protection) *Inspector {
	insp := &Inspector{
		enabled: l7c.Enabled && l7c.PayloadInspection.Enabled,
		mode:    l7c.PayloadInspection.Mode,
	}
	if !insp.enabled {
		return insp
	}
	insp.detector = NewProtocolDetector(l7c.PayloadInspection.Mode)
	for _, cr := range l7c.PayloadInspection.CustomRules {
		rule := CustomRule{
			Name: cr.Name, MatchOffset: cr.MatchOffset, Action: cr.Action,
		}
		rule.MatchBytes, _ = parseHexBytes(cr.MatchBytes)
		if len(rule.MatchBytes) > 0 {
			insp.customRules = append(insp.customRules, rule)
		}
	}
	return insp
}

func (insp *Inspector) Inspect(payload []byte) bool {
	if !insp.enabled {
		return true
	}
	insp.mu.RLock()
	defer insp.mu.RUnlock()
	for _, rule := range insp.customRules {
		if len(payload) >= rule.MatchOffset+len(rule.MatchBytes) {
			chunk := payload[rule.MatchOffset : rule.MatchOffset+len(rule.MatchBytes)]
			if bytes.Equal(chunk, rule.MatchBytes) {
				if rule.Action == "drop" {
					insp.dropped.Add(1)
					return false
				}
				insp.passed.Add(1)
				return true
			}
		}
	}
	if insp.detector != nil && insp.detector.Mode() != "none" && insp.detector.Mode() != "" {
		if insp.detector.Check(payload) {
			insp.passed.Add(1)
			return true
		}
		insp.dropped.Add(1)
		return false
	}
	insp.passed.Add(1)
	return true
}

func (insp *Inspector) Passed() int64   { return insp.passed.Load() }
func (insp *Inspector) Dropped() int64  { return insp.dropped.Load() }
func (insp *Inspector) IsEnabled() bool { return insp.enabled }

func parseHexBytes(s string) ([]byte, error) {
	parts := strings.Split(s, ",")
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "0x")
		p = strings.TrimPrefix(p, "0X")
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

type banEntry struct {
	IP        net.IP
	ExpiresAt int64 // unix nano; 0 = permanent
	Reason    string
}

type banStore struct {
	mu   sync.RWMutex
	bans map[string]banEntry
}

func newBanStore() *banStore {
	return &banStore{bans: make(map[string]banEntry)}
}

// FIX #2: IsBanned now correctly checks ExpiresAt and auto-removes expired bans.
// Previously it only checked map membership, so bans never expired.
func (bs *banStore) IsBanned(ip net.IP) bool {
	if ip == nil {
		return false
	}
	key := ip.String()
	bs.mu.RLock()
	e, ok := bs.bans[key]
	bs.mu.RUnlock()
	if !ok {
		return false
	}
	// ExpiresAt == 0 means permanent ban.
	if e.ExpiresAt == 0 {
		return true
	}
	// Check if the ban has expired.
	if nowNanosBan() > e.ExpiresAt {
		// Upgrade to write lock and remove the expired entry.
		bs.mu.Lock()
		// Re-check under write lock (another goroutine may have already removed it).
		if entry, still := bs.bans[key]; still && entry.ExpiresAt > 0 && nowNanosBan() > entry.ExpiresAt {
			delete(bs.bans, key)
		}
		bs.mu.Unlock()
		return false
	}
	return true
}

func (bs *banStore) Ban(ip net.IP, expiresAt int64, reason string) {
	if ip == nil {
		return
	}
	bs.mu.Lock()
	bs.bans[ip.String()] = banEntry{IP: ip, ExpiresAt: expiresAt, Reason: reason}
	bs.mu.Unlock()
}

func (bs *banStore) Unban(ip net.IP) {
	if ip == nil {
		return
	}
	bs.mu.Lock()
	delete(bs.bans, ip.String())
	bs.mu.Unlock()
}

func (bs *banStore) List() []banEntry {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]banEntry, 0, len(bs.bans))
	for _, e := range bs.bans {
		out = append(out, e)
	}
	return out
}

func (bs *banStore) Count() int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return len(bs.bans)
}

// nowNanosBan returns unix nanoseconds — separate from nowNanos() in lb package.
func nowNanosBan() int64 {
	// Use sync/atomic-safe time; avoids importing time package ambiguity.
	// This is just time.Now().UnixNano() wrapped to keep the package-level call
	// explicit and testable.
	return timeNowUnixNano()
}
