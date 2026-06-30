package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/bandwidth"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/health"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/l7"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/lb"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Instance struct {
	Name   string
	Config *config.Proxy
	global *config.Global
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	tcp      []*TCPProxy
	udp      []*UDPProxy
	balancer *BalancerAdapter
	tracker  *ConnTracker
	checker  *health.Checker

	cancel context.CancelFunc
	eg     *errgroup.Group

	// bwTracker is stored here so Stop() can call Close() to stop the cleanup goroutine.
	bwTracker *bandwidth.Tracker

	// l7Engine is stored here so Stop() can stop its cleanup goroutine.
	l7Engine *l7.Engine
}

type Manager struct {
	global *config.Global
	logger *zap.Logger

	mu        sync.RWMutex
	instances map[string]*Instance

	onInstanceStart func(*Instance)
	onInstanceStop  func(*Instance)

	globalACL         ACLChecker
	proxyACLs         map[string]ACLChecker
	bandwidthTrackers map[string]*bandwidth.Tracker
	l7Engines         map[string]*l7.Engine
}

func NewManager(global *config.Global, logger *zap.Logger) *Manager {
	return &Manager{
		global:            global,
		logger:            logger,
		instances:         make(map[string]*Instance),
		proxyACLs:         make(map[string]ACLChecker),
		bandwidthTrackers: make(map[string]*bandwidth.Tracker),
		l7Engines:         make(map[string]*l7.Engine),
	}
}

func (m *Manager) SetHooks(onStart, onStop func(*Instance)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onInstanceStart = onStart
	m.onInstanceStop = onStop
}

func (m *Manager) SetGlobalACL(acl ACLChecker)             { m.mu.Lock(); m.globalACL = acl; m.mu.Unlock() }
func (m *Manager) SetProxyACL(name string, acl ACLChecker) { m.mu.Lock(); m.proxyACLs[name] = acl; m.mu.Unlock() }
func (m *Manager) GetProxyACL(name string) ACLChecker       { m.mu.RLock(); defer m.mu.RUnlock(); return m.proxyACLs[name] }
func (m *Manager) GetBandwidthTracker(name string) *bandwidth.Tracker {
	m.mu.RLock(); defer m.mu.RUnlock(); return m.bandwidthTrackers[name]
}
func (m *Manager) AllBandwidthTrackers() map[string]*bandwidth.Tracker {
	m.mu.RLock(); defer m.mu.RUnlock()
	out := make(map[string]*bandwidth.Tracker, len(m.bandwidthTrackers))
	for k, v := range m.bandwidthTrackers { out[k] = v }
	return out
}
func (m *Manager) GetL7Engine(name string) *l7.Engine {
	m.mu.RLock(); defer m.mu.RUnlock(); return m.l7Engines[name]
}
func (m *Manager) AllL7Engines() map[string]*l7.Engine {
	m.mu.RLock(); defer m.mu.RUnlock()
	out := make(map[string]*l7.Engine, len(m.l7Engines))
	for k, v := range m.l7Engines { out[k] = v }
	return out
}

func (m *Manager) getComposedACL(proxyName string) ACLChecker {
	m.mu.RLock()
	globalACL := m.globalACL
	proxyACL := m.proxyACLs[proxyName]
	m.mu.RUnlock()
	if globalACL == nil && proxyACL == nil { return nil }
	if globalACL == nil { return proxyACL }
	if proxyACL == nil { return globalACL }
	return &composedACL{first: globalACL, second: proxyACL}
}

type composedACL struct{ first, second ACLChecker }

func (c *composedACL) Check(ip net.IP) string {
	if c.first.Check(ip) == "deny" { return "deny" }
	return c.second.Check(ip)
}

// dynamicACL resolves the composed ACL for a proxy on every Check, rather than
// snapshotting it at build time. This is required because the per-proxy ACL is
// registered (via SetProxyACL) by the manager's onInstanceStart hook, which
// runs AFTER buildInstance returns — a static snapshot taken in buildInstance
// would always miss it, silently disabling per-proxy ACL rules for live traffic.
type dynamicACL struct {
	mgr  *Manager
	name string
}

func (d *dynamicACL) Check(ip net.IP) string {
	c := d.mgr.getComposedACL(d.name)
	if c == nil {
		return "allow"
	}
	return c.Check(ip)
}

func (m *Manager) Start(proxy *config.Proxy) error {
	// If an instance with this name already exists, stop it first. We must not
	// hold m.mu while building the instance: buildInstance calls
	// getComposedACL (RLock) and registers the bandwidth tracker (Lock), and
	// Go's sync.RWMutex is NOT reentrant — holding the write lock here and
	// re-acquiring it inside buildInstance self-deadlocks the goroutine.
	m.mu.RLock()
	_, exists := m.instances[proxy.Name]
	m.mu.RUnlock()
	if exists {
		m.Stop(proxy.Name)
	}
	inst, err := m.buildInstance(proxy)
	if err != nil {
		return fmt.Errorf("proxy %s: build failed: %w", proxy.Name, err)
	}
	m.mu.Lock()
	m.instances[proxy.Name] = inst
	m.mu.Unlock()
	if err := inst.Start(); err != nil {
		m.mu.Lock(); delete(m.instances, proxy.Name); m.mu.Unlock()
		return fmt.Errorf("proxy %s: start failed: %w", proxy.Name, err)
	}
	if m.onInstanceStart != nil { m.onInstanceStart(inst) }
	m.logger.Info("proxy started", zap.String("name", proxy.Name))
	return nil
}

func (m *Manager) Stop(name string) {
	m.mu.Lock()
	inst, ok := m.instances[name]
	if !ok { m.mu.Unlock(); return }
	delete(m.instances, name)
	delete(m.l7Engines, name)
	delete(m.bandwidthTrackers, name)
	delete(m.proxyACLs, name)
	m.mu.Unlock()
	if m.onInstanceStop != nil { m.onInstanceStop(inst) }
	inst.Stop()
	m.logger.Info("proxy stopped", zap.String("name", name))
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	insts := m.instances
	m.instances = make(map[string]*Instance)
	m.l7Engines = make(map[string]*l7.Engine)
	m.bandwidthTrackers = make(map[string]*bandwidth.Tracker)
	m.proxyACLs = make(map[string]ACLChecker)
	m.mu.Unlock()
	for name, inst := range insts {
		if m.onInstanceStop != nil { m.onInstanceStop(inst) }
		inst.Stop()
		m.logger.Info("proxy stopped", zap.String("name", name))
	}
}

func (m *Manager) Get(name string) *Instance    { m.mu.RLock(); defer m.mu.RUnlock(); return m.instances[name] }

// NameByConfigPath returns the name of the running proxy whose config was loaded
// from the supplied file path, or "" if none. Used by the hot-reload watcher to
// stop a proxy when its config file is deleted (the file is gone, so the name
// can no longer be parsed from disk).
func (m *Manager) NameByConfigPath(path string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for name, inst := range m.instances {
		if inst.Config != nil && inst.Config.ConfigPath == path {
			return name
		}
	}
	return ""
}
func (m *Manager) List() []string {
	m.mu.RLock(); defer m.mu.RUnlock()
	names := make([]string, 0, len(m.instances))
	for name := range m.instances { names = append(names, name) }
	return names
}

type timeouts struct {
	UpstreamConnect, UpstreamRead, UpstreamWrite time.Duration
	ClientRead, ClientWrite, UDPSessionTimeout   time.Duration
}

func (m *Manager) resolveTimeouts(proxy *config.Proxy) timeouts {
	gd := m.global.Defaults
	pt := proxy.Timeouts
	return timeouts{
		UpstreamConnect:   time.Duration(pt.UpstreamConnect.Or(config.Duration(gd.UpstreamConnectTimeout))),
		UpstreamRead:      time.Duration(pt.UpstreamRead.Or(config.Duration(gd.UpstreamReadTimeout))),
		UpstreamWrite:     time.Duration(pt.UpstreamWrite.Or(config.Duration(gd.UpstreamWriteTimeout))),
		ClientRead:        time.Duration(pt.ClientRead.Or(config.Duration(gd.ClientReadTimeout))),
		ClientWrite:       time.Duration(pt.ClientWrite.Or(config.Duration(gd.ClientWriteTimeout))),
		UDPSessionTimeout: time.Duration(pt.UDPSessionTimeout.Or(config.Duration(gd.UDPSessionTimeout))),
	}
}

func (m *Manager) buildInstance(proxy *config.Proxy) (*Instance, error) {
	originIPStrs := proxy.ResolveOriginIPs()
	destIPStrs := proxy.ResolveDestIPs()
	originPorts := proxy.ResolveOriginPorts()
	destPorts := proxy.ResolveDestPorts()

	if len(originIPStrs) == 0 || len(destIPStrs) == 0 {
		return nil, fmt.Errorf("no origin or dest IPs resolved")
	}
	if len(originPorts) == 0 || len(destPorts) == 0 {
		return nil, fmt.Errorf("no ports resolved")
	}

	originIPs := make([]net.IP, 0, len(originIPStrs))
	for _, s := range originIPStrs {
		ip := net.ParseIP(s)
		if ip == nil { return nil, fmt.Errorf("invalid origin IP %q", s) }
		originIPs = append(originIPs, ip)
	}
	destIPs := make([]net.IP, 0, len(destIPStrs))
	for _, s := range destIPStrs {
		ip := net.ParseIP(s)
		if ip == nil { return nil, fmt.Errorf("invalid dest IP %q", s) }
		destIPs = append(destIPs, ip)
	}

	resolver, err := NewResolver(originPorts, destPorts, proxy.OneToOne)
	if err != nil { return nil, fmt.Errorf("port resolver: %w", err) }

	weights := proxy.LoadBalancing.UpstreamWeights
	targets := make([]*lb.Target, 0, len(destIPs)*len(destPorts))
	for _, dip := range destIPs {
		for _, dport := range destPorts {
			w := 1
			if val, ok := weights[dip.String()]; ok { w = val }
			targets = append(targets, lb.NewTarget(dip, dport, w, true))
		}
	}

	bal, err := lb.New(proxy.LoadBalancing.Algorithm, targets,
		proxy.LoadBalancing.StickySessions, proxy.LoadBalancing.StickyTTL)
	if err != nil { return nil, fmt.Errorf("balancer: %w", err) }

	balancerAdapter := NewBalancerAdapter(bal)
	tracker := NewConnTracker()
	instLogger := m.logger.With(zap.String("proxy", proxy.Name))
	timeouts := m.resolveTimeouts(proxy)
	// Resolve the composed ACL dynamically per-connection (see dynamicACL).
	var aclChecker ACLChecker = &dynamicACL{mgr: m, name: proxy.Name}
	accessLog := proxy.Logging.LogConnections

	// Bandwidth tracker — stored on Instance so Stop() can close it.
	var bwRec BytesRecorder
	var bwTracker *bandwidth.Tracker
	if proxy.Bandwidth.Enabled && !proxy.Bandwidth.IsZero() {
		loc := time.UTC
		if m.global.Timezone != "" {
			if l, err := time.LoadLocation(m.global.Timezone); err == nil { loc = l }
		}
		bwTracker = bandwidth.NewTracker(proxy.Name, bandwidth.Quota{
			Hourly: proxy.Bandwidth.HourlyLimit, Daily: proxy.Bandwidth.DailyLimit,
			Weekly: proxy.Bandwidth.WeeklyLimit, Monthly: proxy.Bandwidth.MonthlyLimit,
		}, loc)
		bwRec = bwTracker
		// buildInstance no longer runs under m.mu, so guard this map write.
		m.mu.Lock()
		m.bandwidthTrackers[proxy.Name] = bwTracker
		m.mu.Unlock()
	}

	// L7 protection engine — created here (before the proxies) and assigned to
	// each TCP/UDP proxy so it actually inspects live traffic. Previously the
	// engine was built in main.go's onInstanceStart hook and only exposed to the
	// REST API, so payload inspection / behavioral bans never ran on connections.
	var l7Engine *l7.Engine
	if proxy.L7Protection.Enabled {
		l7Engine = l7.NewEngine(proxy.L7Protection)
		m.mu.Lock()
		m.l7Engines[proxy.Name] = l7Engine
		m.mu.Unlock()
	}

	var tcpProxies []*TCPProxy
	var udpProxies []*UDPProxy

	for _, originIP := range originIPs {
		for _, port := range originPorts {
			switch proxy.Protocol {
			case "tcp", "tcp-udp":
				tcp, err := NewTCPProxy(proxy.Name, originIP, TCPConfig{
					OriginPort:           port,
					ConnectTimeout:       timeouts.UpstreamConnect,
					ReadTimeout:          timeouts.UpstreamRead,
					WriteTimeout:         timeouts.UpstreamWrite,
					ClientReadTimeout:    timeouts.ClientRead,
					ClientWriteTimeout:   timeouts.ClientWrite,
					TCPKeepalive:         m.global.Network.TCPKeepaliveEnabled,
					TCPKeepaliveInterval: time.Duration(m.global.Network.TCPKeepaliveInterval) * time.Second,
					TCPNoDelay:           m.global.Network.TCPNoDelay,
					SocketBufferSize:     m.global.Network.SocketBufferSize,
					AccessLog:            accessLog,
				}, balancerAdapter, resolver, tracker, instLogger, aclChecker, bwRec)
				if err != nil { return nil, fmt.Errorf("tcp proxy port %d: %w", port, err) }
				if l7Engine != nil { tcp.l7 = l7Engine }
				tcpProxies = append(tcpProxies, tcp)
			}
			if proxy.Protocol == "udp" || proxy.Protocol == "tcp-udp" {
				udp, err := NewUDPProxy(proxy.Name, originIP, UDPConfig{
					OriginPort:      port,
					ReadBufferSize:  m.global.Network.UDPReadBuffer,
					WriteBufferSize: m.global.Network.UDPWriteBuffer,
					SessionTimeout:  timeouts.UDPSessionTimeout,
				}, balancerAdapter, resolver, tracker, instLogger, aclChecker, bwRec)
				if err != nil { return nil, fmt.Errorf("udp proxy port %d: %w", port, err) }
				if l7Engine != nil { udp.l7 = l7Engine }
				udpProxies = append(udpProxies, udp)
			}
		}
	}

	healthTargets := make([]health.Target, 0, len(targets))
	for _, t := range targets {
		healthTargets = append(healthTargets, health.Target{IP: t.IP, Port: t.Port})
	}

	hcOverride := proxy.LoadBalancing.HealthCheck
	hcCfg := health.Config{
		Interval:            time.Duration(m.global.Defaults.HealthCheckInterval),
		Timeout:             time.Duration(m.global.Defaults.HealthCheckTimeout),
		FailuresBeforeEject: m.global.Defaults.HealthCheckFailuresBeforeEject,
		PassesBeforeReadmit: m.global.Defaults.HealthCheckPassesBeforeReadmit,
	}
	if hcOverride.Interval > 0 { hcCfg.Interval = time.Duration(hcOverride.Interval) }
	if hcOverride.Timeout > 0 { hcCfg.Timeout = time.Duration(hcOverride.Timeout) }
	if hcOverride.FailuresBeforeEject > 0 { hcCfg.FailuresBeforeEject = hcOverride.FailuresBeforeEject }
	if hcOverride.PassesBeforeReadmit > 0 { hcCfg.PassesBeforeReadmit = hcOverride.PassesBeforeReadmit }

	// Active health checks dial TCP. For a UDP-only proxy that probe is
	// meaningless and will permanently eject the (UDP-only) upstream, starving
	// all UDP traffic. So we skip the checker for udp-only proxies and leave
	// every upstream healthy (matching HAProxy's default UDP behavior). tcp and
	// tcp-udp proxies still get real TCP health checking.
	var checker *health.Checker
	if proxy.Protocol != "udp" {
		checker, err = health.New(hcCfg, healthTargets, bal.SetHealth, instLogger)
		if err != nil { return nil, fmt.Errorf("health checker: %w", err) }
	}

	// FIX: sticky table cleanup goroutine is now bound to the instance context
	// so it stops when the proxy stops (previously leaked forever).
	if proxy.LoadBalancing.StickySessions {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				bal.PruneStickyTable()
			}
		}()
	}

	return &Instance{
		Name: proxy.Name, Config: proxy, global: m.global, logger: instLogger,
		tcp: tcpProxies, udp: udpProxies, balancer: balancerAdapter,
		tracker: tracker, checker: checker, bwTracker: bwTracker,
		l7Engine: l7Engine,
	}, nil
}

func (inst *Instance) Start() error {
	inst.mu.Lock(); defer inst.mu.Unlock()
	if inst.running { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	inst.cancel = cancel
	eg, egCtx := errgroup.WithContext(ctx)
	inst.eg = eg
	if inst.checker != nil {
		if err := inst.checker.Start(egCtx); err != nil { cancel(); return err }
	}
	for _, tcp := range inst.tcp {
		tcp := tcp; eg.Go(func() error { return tcp.Start(egCtx) })
	}
	for _, udp := range inst.udp {
		udp := udp; eg.Go(func() error { return udp.Start(egCtx) })
	}
	inst.running = true
	return nil
}

// Stop drains all connections and releases all resources.
func (inst *Instance) Stop() {
	inst.mu.Lock()
	if !inst.running {
		inst.mu.Unlock()
		return
	}
	inst.running = false
	cancel := inst.cancel
	eg := inst.eg
	tcp := make([]*TCPProxy, len(inst.tcp))
	copy(tcp, inst.tcp)
	udp := make([]*UDPProxy, len(inst.udp))
	copy(udp, inst.udp)
	checker := inst.checker
	bwTracker := inst.bwTracker
	l7Engine := inst.l7Engine
	inst.mu.Unlock()

	if checker != nil {
		checker.Stop()
	}
	if cancel != nil { cancel() }

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer drainCancel()
	for _, p := range tcp { p.Stop(drainCtx) }
	for _, p := range udp { p.Stop(drainCtx) }
	if eg != nil { _ = eg.Wait() }

	// FIX: close bandwidth tracker to stop its hourly cleanup goroutine.
	if bwTracker != nil {
		bwTracker.Close()
	}
	// Stop the L7 engine's cleanup goroutine to prevent a goroutine leak.
	if l7Engine != nil {
		l7Engine.Stop()
	}
}

func (inst *Instance) IsRunning() bool { inst.mu.RLock(); defer inst.mu.RUnlock(); return inst.running }
func (inst *Instance) Balancer() *BalancerAdapter { return inst.balancer }
func (inst *Instance) Tracker() *ConnTracker      { return inst.tracker }
func (inst *Instance) TCPProxies() []*TCPProxy {
	inst.mu.RLock(); defer inst.mu.RUnlock()
	out := make([]*TCPProxy, len(inst.tcp)); copy(out, inst.tcp); return out
}
func (inst *Instance) UDPProxies() []*UDPProxy {
	inst.mu.RLock(); defer inst.mu.RUnlock()
	out := make([]*UDPProxy, len(inst.udp)); copy(out, inst.udp); return out
}
