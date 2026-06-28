package l7

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"sync"

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
	passed      int64
	dropped     int64
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
					insp.dropped++
					return false
				}
				insp.passed++
				return true
			}
		}
	}
	if insp.detector != nil && insp.detector.Mode() != "none" && insp.detector.Mode() != "" {
		if insp.detector.Check(payload) {
			insp.passed++
			return true
		}
		insp.dropped++
		return false
	}
	insp.passed++
	return true
}

func (insp *Inspector) Passed() int64  { return insp.passed }
func (insp *Inspector) Dropped() int64 { return insp.dropped }
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
	ExpiresAt int64
	Reason    string
}

type banStore struct {
	mu   sync.RWMutex
	bans map[string]banEntry
}

func newBanStore() *banStore {
	return &banStore{bans: make(map[string]banEntry)}
}

func (bs *banStore) IsBanned(ip net.IP) bool {
	if ip == nil {
		return false
	}
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	_, ok := bs.bans[ip.String()]
	return ok
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
