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

func (c *Collector) Stop() { close(c.stop) }

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
	var totalActive, totalConns, totalBytesIn, totalBytesOut int64
	for _, name := range names {
		inst := c.manager.Get(name)
		if inst == nil || !inst.IsRunning() {
			continue
		}
		var active int64
		var bytesIn, bytesOut int64
		for _, p := range inst.TCPProxies() {
			active += p.ActiveConns()
			bytesIn += p.BytesIn()
			bytesOut += p.BytesOut()
		}
		for _, p := range inst.UDPProxies() {
			active += p.ActiveConns()
			bytesIn += p.BytesIn()
			bytesOut += p.BytesOut()
		}
		c.store.Set(name, func(m *ProxyMetrics) {
			m.ActiveConnections = active
			m.BytesIn = bytesIn
			m.BytesOut = bytesOut
		})
		upstreams := inst.Balancer().Snapshot()
		for _, u := range upstreams {
			key := u.IP.String() + ":" + itoa(u.Port)
			c.store.Set(name, func(m *ProxyMetrics) {
				if m.Upstreams == nil {
					m.Upstreams = make(map[string]*UpstreamMetrics)
				}
				um, ok := m.Upstreams[key]
				if !ok {
					um = &UpstreamMetrics{IP: u.IP.String(), Port: u.Port}
					m.Upstreams[key] = um
				}
				um.ActiveConns = u.ActiveConns
				um.TotalConns = u.TotalConns
				um.FailCount = u.FailCount
				if u.Healthy {
					um.Healthy = 1
				} else {
					um.Healthy = 0
				}
			})
		}
		totalActive += active
		totalBytesIn += bytesIn
		totalBytesOut += bytesOut
	}
	totalConns += 0
	c.store.UpdateGlobal(func(g *GlobalMetrics) {
		g.ActiveConnections = totalActive
		g.TotalBytesIn = totalBytesIn
		g.TotalBytesOut = totalBytesOut
	})
	_ = totalConns
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
