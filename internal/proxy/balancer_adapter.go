package proxy

import (
	"net"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/lb"
)

// BalancerAdapter wraps lb.Balancer for use by proxy engines.
type BalancerAdapter struct {
	b *lb.Balancer
}

func NewBalancerAdapter(b *lb.Balancer) *BalancerAdapter {
	return &BalancerAdapter{b: b}
}

func (a *BalancerAdapter) Pick(srcIP net.IP) (*Target, error) {
	if a == nil || a.b == nil {
		return nil, lb.ErrNoHealthyTargets
	}
	t, err := a.b.Pick(srcIP)
	if err != nil {
		return nil, err
	}
	return &Target{t: t}, nil
}

func (a *BalancerAdapter) Release(target *Target) {
	if a == nil || a.b == nil || target == nil {
		return
	}
	a.b.Release(target.t)
}

func (a *BalancerAdapter) Snapshot() []lb.Stats {
	if a == nil || a.b == nil {
		return nil
	}
	return a.b.Snapshot()
}

func (a *BalancerAdapter) SetHealth(ip net.IP, port int, healthy bool) {
	if a == nil || a.b == nil {
		return
	}
	a.b.SetHealth(ip, port, healthy)
}

type Target struct {
	t *lb.Target
}

func (t *Target) IP() net.IP {
	if t == nil || t.t == nil {
		return nil
	}
	return t.t.IP
}

func (t *Target) Port() int {
	if t == nil || t.t == nil {
		return 0
	}
	return t.t.Port
}
