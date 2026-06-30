package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// BytesRecorder is notified about bytes transferred. Bandwidth trackers implement this.
type BytesRecorder interface {
	RecordIn(n int64)
	RecordOut(n int64)
}

type TCPProxy struct {
	cfg       TCPConfig
	listener  net.Listener
	balancer  *BalancerAdapter
	resolver  *Resolver
	tracker   *ConnTracker
	drainer   *Drainer
	logger    *zap.Logger
	proxyName string

	acl   ACLChecker
	bwRec BytesRecorder
	l7    L7Checker

	// FIX: acceptCancel is written by Start() and read by Stop() from different
	// goroutines. Guard it with a mutex to prevent the data race.
	cancelMu     sync.Mutex
	acceptCancel context.CancelFunc
	// acceptCtxPtr stores the running context so handleConn goroutines can use it.
	acceptCtxPtr atomic.Pointer[context.Context]

	activeConns int64
	totalConns  int64
	bytesIn     int64
	bytesOut    int64
}

type ACLChecker interface {
	Check(ip net.IP) string
}

// L7Checker is implemented by the l7.Engine. It gates connections at accept
// time (bans, connection cycling) and inspects the first client payload
// (protocol validation, per-IP payload rate limiting). A nil L7Checker means
// L7 protection is disabled for this proxy — the default.
type L7Checker interface {
	OnAccept(srcIP net.IP) bool
	OnData(srcIP net.IP, payload []byte, inspected *bool) bool
	IsBanned(ip net.IP) bool
	NeedsFirstPayload() bool
}

type TCPConfig struct {
	OriginPort           int
	ConnectTimeout       time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	ClientReadTimeout    time.Duration
	ClientWriteTimeout   time.Duration
	TCPKeepalive         bool
	TCPKeepaliveInterval time.Duration
	TCPNoDelay           bool
	SocketBufferSize     int
	MaxConnDuration      time.Duration
	AccessLog            bool
}

func NewTCPProxy(
	proxyName string, originIP net.IP, cfg TCPConfig,
	balancer *BalancerAdapter, resolver *Resolver,
	tracker *ConnTracker, logger *zap.Logger,
	acl ACLChecker, bwRec BytesRecorder,
) (*TCPProxy, error) {
	addr := &net.TCPAddr{IP: originIP, Port: cfg.OriginPort}
	lc := net.ListenConfig{}
	if cfg.SocketBufferSize > 0 {
		lc.Control = setSocketBuffer(cfg.SocketBufferSize)
	}
	ln, err := lc.Listen(context.Background(), "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	return &TCPProxy{
		cfg: cfg, listener: ln, balancer: balancer, resolver: resolver,
		tracker: tracker, drainer: NewDrainer(30*time.Second, logger),
		logger:    logger.With(zap.String("proxy", proxyName), zap.Int("port", cfg.OriginPort)),
		proxyName: proxyName, acl: acl, bwRec: bwRec,
	}, nil
}

func (p *TCPProxy) Start(ctx context.Context) error {
	acceptCtx, cancel := context.WithCancel(ctx)
	p.cancelMu.Lock()
	p.acceptCancel = cancel
	p.cancelMu.Unlock()
	p.acceptCtxPtr.Store(&acceptCtx)
	defer cancel()
	p.logger.Info("tcp proxy started", zap.String("addr", p.listener.Addr().String()))
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-acceptCtx.Done():
				return nil
			default:
				p.logger.Error("tcp accept error", zap.Error(err))
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-acceptCtx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
		}

		srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		srcAddr := net.ParseIP(srcIP)

		// Bandwidth suspension: when the proxy has exceeded its quota it must
		// stop accepting/forwarding traffic entirely. Reject new connections.
		if isSuspended(p.bwRec) {
			if p.cfg.AccessLog {
				p.logger.Info("connection rejected — proxy suspended (bandwidth quota)",
					zap.String("src", srcIP), zap.String("proxy", p.proxyName))
			}
			conn.Close()
			continue
		}

		if p.acl != nil && p.acl.Check(srcAddr) == "deny" {
			if p.cfg.AccessLog {
				p.logger.Info("connection denied by ACL",
					zap.String("src", srcIP), zap.String("proxy", p.proxyName))
			}
			conn.Close()
			continue
		}

		// L7 accept-time gate: banned IPs and connection-cycling abuse are
		// rejected before we spend resources dialing the upstream.
		if p.l7 != nil && !p.l7.OnAccept(srcAddr) {
			if p.cfg.AccessLog {
				p.logger.Info("connection blocked by L7 (accept)",
					zap.String("src", srcIP), zap.String("proxy", p.proxyName))
			}
			conn.Close()
			continue
		}

		if p.cfg.AccessLog {
			p.logger.Info("connection accepted",
				zap.String("src", srcIP), zap.String("proxy", p.proxyName))
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if p.cfg.TCPNoDelay {
				_ = tcpConn.SetNoDelay(true)
			}
			if p.cfg.TCPKeepalive {
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(p.cfg.TCPKeepaliveInterval)
			}
		}

		done := p.drainer.Track()
		atomic.AddInt64(&p.activeConns, 1)
		atomic.AddInt64(&p.totalConns, 1)
		go func() {
			defer done()
			defer atomic.AddInt64(&p.activeConns, -1)
			p.handleConn(conn)
		}()
	}
}

func (p *TCPProxy) handleConn(client net.Conn) {
	defer client.Close()

	srcIP, srcPort, _ := net.SplitHostPort(client.RemoteAddr().String())
	srcAddr := net.ParseIP(srcIP)

	target, err := p.balancer.Pick(srcAddr)
	if err != nil {
		return
	}
	defer p.balancer.Release(target)

	// Dest port selection depends on mapping mode:
	//   one-to-one: the dest port is fixed by the resolver's positional pairing
	//     (origin port → single dest port); the balancer only chooses the IP.
	//   fan-out:    the balancer's chosen target already encodes the dest port
	//     (targets are the full destIP×destPort cross-product), so we must use
	//     target.Port(). Previously destPorts[0] was always used, which pinned
	//     every fan-out connection to the first dest port and defeated load
	//     balancing across ports.
	var destPort int
	if p.resolver.IsOneToOne() {
		destPorts, err := p.resolver.DestPortsFor(p.cfg.OriginPort)
		if err != nil || len(destPorts) == 0 {
			return
		}
		destPort = destPorts[0]
	} else {
		destPort = target.Port()
	}
	upstreamAddr := net.JoinHostPort(target.IP().String(), itoa(destPort))

	connInfo := &ConnInfo{
		ProxyName:    p.proxyName,
		Protocol:     "tcp",
		SrcIP:        srcAddr,
		SrcPort:      parsePort(srcPort),
		UpstreamIP:   target.IP(),
		UpstreamPort: destPort, // resolver-determined port (correct for one-to-one)
		StartedAt:    time.Now(),
	}
	connInfo = p.tracker.Register(connInfo)
	defer func() { connInfo.MarkClosed(); p.tracker.Forget(connInfo.ID) }()

	dialer := net.Dialer{Timeout: p.cfg.ConnectTimeout}
	runCtx := context.Background()
	if ptr := p.acceptCtxPtr.Load(); ptr != nil {
		runCtx = *ptr
	}
	upstream, err := dialer.DialContext(runCtx, "tcp", upstreamAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	// L7 first-payload inspection: read the initial client payload, validate it
	// (protocol detection + per-IP payload rate limiting), then forward it to the
	// upstream before starting the bidirectional copy. Adds a single extra read on
	// the first chunk only — no latency for the steady-state stream. A client that
	// sends nothing within the read deadline is dropped (slow-connection defense).
	if p.l7 != nil && p.l7.NeedsFirstPayload() {
		deadline := p.cfg.ClientReadTimeout
		if deadline <= 0 {
			deadline = 5 * time.Second
		}
		_ = client.SetReadDeadline(time.Now().Add(deadline))
		first := make([]byte, 4096)
		n, rerr := client.Read(first)
		_ = client.SetReadDeadline(time.Time{})
		if n > 0 {
			inspected := false
			if !p.l7.OnData(srcAddr, first[:n], &inspected) {
				if p.cfg.AccessLog {
					p.logger.Info("connection dropped by L7 (payload)",
						zap.String("src", srcIP), zap.String("proxy", p.proxyName))
				}
				return
			}
			if _, werr := upstream.Write(first[:n]); werr != nil {
				return
			}
			atomic.AddInt64(&p.bytesIn, int64(n))
			atomic.AddInt64(&connInfo.bytesIn, int64(n))
			if p.bwRec != nil {
				p.bwRec.RecordIn(int64(n))
			}
		}
		if rerr != nil {
			return
		}
	}

	errCh := make(chan error, 2)

	// client → upstream (inbound)
	go func() {
		n, e := io.Copy(upstream, client)
		atomic.AddInt64(&p.bytesIn, n)
		atomic.AddInt64(&connInfo.bytesIn, n)
		if p.bwRec != nil {
			p.bwRec.RecordIn(n)
		}
		errCh <- e
	}()

	// upstream → client (outbound)
	go func() {
		n, e := io.Copy(client, upstream)
		atomic.AddInt64(&p.bytesOut, n)
		atomic.AddInt64(&connInfo.bytesOut, n)
		if p.bwRec != nil {
			p.bwRec.RecordOut(n)
		}
		errCh <- e
	}()

	<-errCh
	client.Close()
	upstream.Close()

	if p.cfg.AccessLog {
		p.logger.Info("connection closed",
			zap.String("src", srcIP),
			zap.Int64("bytes_in", connInfo.BytesIn()),
			zap.Int64("bytes_out", connInfo.BytesOut()),
			zap.String("proxy", p.proxyName),
			zap.Duration("duration", time.Since(connInfo.StartedAt)))
	}
}

func (p *TCPProxy) Stop(ctx context.Context) {
	p.cancelMu.Lock()
	cancel := p.acceptCancel
	p.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = p.listener.Close()
	p.drainer.Wait(ctx)
}

func (p *TCPProxy) ActiveConns() int64  { return atomic.LoadInt64(&p.activeConns) }
func (p *TCPProxy) TotalConns() int64   { return atomic.LoadInt64(&p.totalConns) }
func (p *TCPProxy) BytesIn() int64      { return atomic.LoadInt64(&p.bytesIn) }
func (p *TCPProxy) BytesOut() int64     { return atomic.LoadInt64(&p.bytesOut) }
func (p *TCPProxy) OriginPort() int     { return p.cfg.OriginPort }
