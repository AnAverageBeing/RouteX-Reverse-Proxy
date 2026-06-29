package proxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type UDPProxy struct {
	cfg       UDPConfig
	conn      *net.UDPConn
	balancer  *BalancerAdapter
	resolver  *Resolver
	tracker   *ConnTracker
	logger    *zap.Logger
	proxyName string

	// FIX #8: added ACL and bandwidth recorder (were missing — ACL rules silently
	// ignored and UDP bytes never counted toward bandwidth quotas)
	acl   ACLChecker
	bwRec BytesRecorder

	acceptCtx    context.Context
	acceptCancel context.CancelFunc

	sessions   map[string]*udpSession
	sessionsMu sync.RWMutex

	activeConns int64
	totalConns  int64
	bytesIn     int64
	bytesOut    int64
}

type UDPConfig struct {
	OriginPort      int
	ReadBufferSize  int
	WriteBufferSize int
	SessionTimeout  time.Duration
}

type udpSession struct {
	upstream     *net.UDPConn
	upstreamAddr *net.UDPAddr
	target       *Target
	connInfo     *ConnInfo
	lastActivity time.Time
	ctx          context.Context
	cancel       context.CancelFunc
}

// FIX #8: NewUDPProxy now accepts ACL and BytesRecorder parameters.
func NewUDPProxy(
	proxyName string, originIP net.IP, cfg UDPConfig,
	balancer *BalancerAdapter, resolver *Resolver,
	tracker *ConnTracker, logger *zap.Logger,
	acl ACLChecker, bwRec BytesRecorder,
) (*UDPProxy, error) {
	addr := &net.UDPAddr{IP: originIP, Port: cfg.OriginPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	if cfg.ReadBufferSize > 0 {
		_ = conn.SetReadBuffer(cfg.ReadBufferSize)
	}
	if cfg.WriteBufferSize > 0 {
		_ = conn.SetWriteBuffer(cfg.WriteBufferSize)
	}
	// Use a minimum 1-second session timeout to avoid zero-duration ticker panic.
	if cfg.SessionTimeout < time.Second {
		cfg.SessionTimeout = 60 * time.Second
	}
	return &UDPProxy{
		cfg: cfg, conn: conn, balancer: balancer, resolver: resolver,
		tracker: tracker,
		logger: logger.With(
			zap.String("proxy", proxyName),
			zap.Int("port", cfg.OriginPort),
			zap.String("proto", "udp"),
		),
		proxyName: proxyName,
		sessions:  make(map[string]*udpSession),
		acl:       acl,
		bwRec:     bwRec,
	}, nil
}

func (p *UDPProxy) Start(ctx context.Context) error {
	p.acceptCtx, p.acceptCancel = context.WithCancel(ctx)
	defer p.acceptCancel()
	go p.reapSessions()
	p.logger.Info("udp proxy started", zap.String("addr", p.conn.LocalAddr().String()))
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.acceptCtx.Done():
				return nil
			default:
				continue
			}
		}

		// FIX #8: ACL check per source IP for UDP (was completely missing before)
		if p.acl != nil && p.acl.Check(remoteAddr.IP) == "deny" {
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])
		atomic.AddInt64(&p.bytesIn, int64(n))
		// FIX #8: record inbound bytes toward bandwidth quota
		if p.bwRec != nil {
			p.bwRec.RecordIn(int64(n))
		}

		key := remoteAddr.String()
		sess := p.getOrCreateSession(remoteAddr, key)
		if sess == nil {
			continue
		}
		_, err = sess.upstream.Write(payload)
		if err != nil {
			p.logger.Debug("udp write upstream failed",
				zap.String("upstream", sess.upstreamAddr.String()),
				zap.Error(err))
		}
	}
}

func (p *UDPProxy) getOrCreateSession(clientAddr *net.UDPAddr, key string) *udpSession {
	p.sessionsMu.RLock()
	sess, ok := p.sessions[key]
	p.sessionsMu.RUnlock()
	if ok {
		sess.lastActivity = time.Now()
		return sess
	}
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()
	if sess, ok = p.sessions[key]; ok {
		sess.lastActivity = time.Now()
		return sess
	}
	target, err := p.balancer.Pick(clientAddr.IP)
	if err != nil {
		return nil
	}
	destPorts, err := p.resolver.DestPortsFor(p.cfg.OriginPort)
	if err != nil || len(destPorts) == 0 {
		p.balancer.Release(target)
		return nil
	}
	// FIX #4 (UDP side): use the resolver-determined dest port for one-to-one
	// mapping. destPorts[0] is the correct mapped port for this origin port.
	destPort := destPorts[0]
	upstreamAddr := &net.UDPAddr{IP: target.IP(), Port: destPort}
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		p.balancer.Release(target)
		return nil
	}
	ctx, cancel := context.WithCancel(p.acceptCtx)
	connInfo := &ConnInfo{
		ProxyName: p.proxyName, Protocol: "udp",
		SrcIP: clientAddr.IP, SrcPort: clientAddr.Port,
		UpstreamIP: target.IP(), UpstreamPort: destPort,
		StartedAt: time.Now(),
	}
	connInfo = p.tracker.Register(connInfo)
	sess = &udpSession{
		upstream: upstreamConn, upstreamAddr: upstreamAddr,
		target: target, connInfo: connInfo,
		lastActivity: time.Now(), ctx: ctx, cancel: cancel,
	}
	p.sessions[key] = sess
	atomic.AddInt64(&p.activeConns, 1)
	atomic.AddInt64(&p.totalConns, 1)
	go p.readUpstream(key, sess, clientAddr)
	return sess
}

func (p *UDPProxy) readUpstream(key string, sess *udpSession, clientAddr *net.UDPAddr) {
	defer func() {
		sess.cancel()
		sess.upstream.Close()
		p.balancer.Release(sess.target)
		sess.connInfo.MarkClosed()
		p.tracker.Forget(sess.connInfo.ID)
		p.sessionsMu.Lock()
		delete(p.sessions, key)
		p.sessionsMu.Unlock()
		atomic.AddInt64(&p.activeConns, -1)
	}()
	buf := make([]byte, 65535)
	for {
		select {
		case <-sess.ctx.Done():
			return
		default:
		}
		_ = sess.upstream.SetReadDeadline(time.Now().Add(p.cfg.SessionTimeout))
		n, _, err := sess.upstream.ReadFromUDP(buf)
		if err != nil {
			return
		}
		atomic.AddInt64(&p.bytesOut, int64(n))
		atomic.AddInt64(&sess.connInfo.bytesOut, int64(n))
		// FIX #8: record outbound bytes toward bandwidth quota
		if p.bwRec != nil {
			p.bwRec.RecordOut(int64(n))
		}
		_, err = p.conn.WriteToUDP(buf[:n], clientAddr)
		if err != nil {
			return
		}
		sess.lastActivity = time.Now()
	}
}

func (p *UDPProxy) reapSessions() {
	ticker := time.NewTicker(p.cfg.SessionTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-p.acceptCtx.Done():
			return
		case <-ticker.C:
		}
		p.sessionsMu.Lock()
		now := time.Now()
		for key, sess := range p.sessions {
			if now.Sub(sess.lastActivity) > p.cfg.SessionTimeout {
				sess.cancel()
				delete(p.sessions, key)
			}
		}
		p.sessionsMu.Unlock()
	}
}

func (p *UDPProxy) Stop(ctx context.Context) {
	if p.acceptCancel != nil {
		p.acceptCancel()
	}
	_ = p.conn.Close()
	p.sessionsMu.Lock()
	for _, sess := range p.sessions {
		sess.cancel()
	}
	p.sessionsMu.Unlock()
}

func (p *UDPProxy) ActiveConns() int64 { return atomic.LoadInt64(&p.activeConns) }
func (p *UDPProxy) TotalConns() int64  { return atomic.LoadInt64(&p.totalConns) }
func (p *UDPProxy) BytesIn() int64     { return atomic.LoadInt64(&p.bytesIn) }
func (p *UDPProxy) BytesOut() int64    { return atomic.LoadInt64(&p.bytesOut) }
func (p *UDPProxy) OriginPort() int    { return p.cfg.OriginPort }
