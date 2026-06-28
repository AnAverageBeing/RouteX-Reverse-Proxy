package proxy

import (
	"context"
	"io"
	"net"
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

	acl    ACLChecker
	bwRec  BytesRecorder

	acceptCtx    context.Context
	acceptCancel context.CancelFunc

	activeConns int64
	totalConns  int64
	bytesIn     int64
	bytesOut    int64
}

type ACLChecker interface {
	Check(ip net.IP) string
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
	p.acceptCtx, p.acceptCancel = context.WithCancel(ctx)
	defer p.acceptCancel()
	p.logger.Info("tcp proxy started", zap.String("addr", p.listener.Addr().String()))
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.acceptCtx.Done():
				return nil
			default:
				p.logger.Error("tcp accept error", zap.Error(err))
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-p.acceptCtx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
		}

		srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		srcAddr := net.ParseIP(srcIP)

		if p.acl != nil && p.acl.Check(srcAddr) == "deny" {
			if p.cfg.AccessLog {
				p.logger.Info("connection denied by ACL",
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

	destPorts, err := p.resolver.DestPortsFor(p.cfg.OriginPort)
	if err != nil || len(destPorts) == 0 {
		return
	}
	destPort := target.Port()
	_ = destPorts
	upstreamAddr := net.JoinHostPort(target.IP().String(), itoa(destPort))

	connInfo := &ConnInfo{
		ProxyName: p.proxyName, Protocol: "tcp",
		SrcIP: srcAddr, SrcPort: parsePort(srcPort),
		UpstreamIP: target.IP(), UpstreamPort: destPort,
		StartedAt: time.Now(),
	}
	connInfo = p.tracker.Register(connInfo)
	defer func() { connInfo.MarkClosed(); p.tracker.Forget(connInfo.ID) }()

	dialer := net.Dialer{Timeout: p.cfg.ConnectTimeout}
	upstream, err := dialer.DialContext(p.acceptCtx, "tcp", upstreamAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

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
	if p.acceptCancel != nil {
		p.acceptCancel()
	}
	_ = p.listener.Close()
	p.drainer.Wait(ctx)
}

func (p *TCPProxy) ActiveConns() int64  { return atomic.LoadInt64(&p.activeConns) }
func (p *TCPProxy) TotalConns() int64   { return atomic.LoadInt64(&p.totalConns) }
func (p *TCPProxy) BytesIn() int64      { return atomic.LoadInt64(&p.bytesIn) }
func (p *TCPProxy) BytesOut() int64     { return atomic.LoadInt64(&p.bytesOut) }
func (p *TCPProxy) OriginPort() int     { return p.cfg.OriginPort }
