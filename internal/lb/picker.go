package lb

import (
	"fmt"
	"net"
)

// Stats is a read-only snapshot of one target's state. Returned by Snapshot so
// the API layer can render live upstream stats without holding hot-path locks.
type Stats struct {
	IP          net.IP
	Port        int
	Weight      int
	Healthy     bool
	ActiveConns int64
	TotalConns  int64
	FailCount   int64
}

// String renders the snapshot for log/error output.
func (s Stats) String() string {
	host := "<nil>"
	if s.IP != nil {
		host = s.IP.String()
	}
	return fmt.Sprintf("%s:%d healthy=%t active=%d total=%d fail=%d w=%d",
		host, s.Port, s.Healthy, s.ActiveConns, s.TotalConns, s.FailCount, s.Weight)
}

// Snapshot returns a defensive copy of every target's current stats. Used by
// the API and metrics layer; hot-path callers use Target method accessors to
// avoid allocating.
func (b *Balancer) Snapshot() []Stats {
	b.rw.RLock()
	defer b.rw.RUnlock()
	out := make([]Stats, 0, len(b.targets))
	for _, t := range b.targets {
		out = append(out, Stats{
			IP:          t.IP,
			Port:        t.Port,
			Weight:      t.Weight,
			Healthy:     t.IsHealthy(),
			ActiveConns: t.ActiveConns(),
			TotalConns:  t.TotalConns(),
			FailCount:   t.FailCount(),
		})
	}
	return out
}

// NewTarget is a small constructor used by the proxy manager when materializing
// targets from config — keeps Target construction in one place.
func NewTarget(ip net.IP, port int, weight int, healthy bool) *Target {
	t := &Target{IP: ip, Port: port, Weight: weight}
	if healthy {
		t.healthy = 1
	}
	return t
}