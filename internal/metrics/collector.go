package metrics

import (
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/proxy"
	"go.uber.org/zap"
)

type Collector struct {
	store    *Store
	manager  *proxy.Manager
	interval time.Duration
	logger   *zap.Logger
	stop     chan struct{}
}

func NewCollector(store *Store, mgr *proxy.Manager, interval time.Duration, logger *zap.Logger) *Collector {
	return &Collector{
		store: store, manager: mgr, interval: interval, logger: logger,
		stop: make(chan struct{}),
	}
}

func (c *Collector) Start() { go c.loop() }

func (c *Collector) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

func (c *Collector) loop() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.collect()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) collect() {
	names := c.manager.List()

	// FIX #6: track total conns properly across all proxies
	var totalActive, totalBytesIn, totalBytesOut, totalConns int64

	for _, name := range names {
		inst := c.manager.Get(name)
		if inst == nil || !inst.IsRunning() {
			continue
		}

		var active, proxyTotalConns int64
		var bytesIn, bytesOut int64

		for _, p := range inst.TCPProxies() {
			active += p.ActiveConns()
			proxyTotalConns += p.TotalConns()
			bytesIn += p.BytesIn()
			bytesOut += p.BytesOut()
		}
		for _, p := range inst.UDPProxies() {
			active += p.ActiveConns()
			proxyTotalConns += p.TotalConns()
			bytesIn += p.BytesIn()
			bytesOut += p.BytesOut()
		}

		// FIX #5: store values as concrete snapshots rather than holding a
		// pointer to a struct that is concurrently written by proxy goroutines.
		// Use the Set closure to write atomically via the store's own mutex.
		activeSnap := active
		bytesInSnap := bytesIn
		bytesOutSnap := bytesOut
		proxyTotalConnsSnap := proxyTotalConns

		c.store.Set(name, func(m *ProxyMetrics) {
			m.ActiveConnections = activeSnap
			m.TotalConnections = proxyTotalConnsSnap
			m.BytesIn = bytesInSnap
			m.BytesOut = bytesOutSnap
		})

		// Upstream stats from balancer snapshot
		upstreams := inst.Balancer().Snapshot()
		for _, u := range upstreams {
			key := u.IP.String() + ":" + itoa(u.Port)
			uSnap := u // capture for closure
			c.store.Set(name, func(m *ProxyMetrics) {
				if m.Upstreams == nil {
					m.Upstreams = make(map[string]*UpstreamMetrics)
				}
				um, ok := m.Upstreams[key]
				if !ok {
					um = &UpstreamMetrics{IP: uSnap.IP.String(), Port: uSnap.Port}
					m.Upstreams[key] = um
				}
				um.ActiveConns = uSnap.ActiveConns
				um.TotalConns = uSnap.TotalConns
				um.FailCount = uSnap.FailCount
				if uSnap.Healthy {
					um.Healthy = 1
				} else {
					um.Healthy = 0
				}
			})
		}

		totalActive += active
		totalConns += proxyTotalConns
		totalBytesIn += bytesIn
		totalBytesOut += bytesOut
	}

	// FIX #6: TotalConnections was always 0 before because totalConns was never
	// accumulated. Now properly summed above.
	c.store.UpdateGlobal(func(g *GlobalMetrics) {
		g.ActiveConnections = totalActive
		g.TotalConnections = totalConns
		g.TotalBytesIn = totalBytesIn
		g.TotalBytesOut = totalBytesOut
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
