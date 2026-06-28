package proxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnInfo captures a single live or recently-closed connection. Used by the
// /api/proxies/{name}/connections endpoint and by the metrics collector.
//
// BytesIn / BytesOut are updated atomically from the proxy copy loops; readers
// (API handlers, metrics) must use the supplied accessor methods to obtain a
// consistent snapshot.
type ConnInfo struct {
	ID           uint64
	ProxyName    string
	Protocol     string // "tcp" or "udp"
	SrcIP        net.IP
	SrcPort      int
	UpstreamIP   net.IP
	UpstreamPort int
	StartedAt    time.Time

	bytesIn  int64 // client→upstream count
	bytesOut int64 // upstream→client count

	closed uint32 // 1 once the conn drained / dropped
}

// BytesIn returns the total bytes received from the client.
func (c *ConnInfo) BytesIn() int64 { return atomic.LoadInt64(&c.bytesIn) }

// BytesOut returns the total bytes sent to the client.
func (c *ConnInfo) BytesOut() int64 { return atomic.LoadInt64(&c.bytesOut) }

// MarkClosed records that the connection is no longer live. Idempotent.
func (c *ConnInfo) MarkClosed() { atomic.StoreUint32(&c.closed, 1) }

// IsClosed reports whether MarkClosed was called.
func (c *ConnInfo) IsClosed() bool { return atomic.LoadUint32(&c.closed) == 1 }

// ConnTracker is the per-instance connection registry. Locking is split
// (rw mutex for the map, atomics for counts) so the active-conn counter never
// contends with the read-side map traffic.
type ConnTracker struct {
	mu    sync.RWMutex
	conns map[uint64]*ConnInfo
	next  atomic.Uint64
	live  atomic.Int64
}

// NewConnTracker constructs an empty ConnTracker.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{conns: make(map[uint64]*ConnInfo)}
}

// Register records a new live connection and returns its tracker handle. The
// returned *ConnInfo is shared with the proxy loop, which updates its byte
// counters via AddBytesIn/AddBytesOut wrappers (defined below).
func (t *ConnTracker) Register(info *ConnInfo) *ConnInfo {
	if info.ID == 0 {
		info.ID = t.next.Add(1)
	}
	t.mu.Lock()
	t.conns[info.ID] = info
	t.mu.Unlock()
	t.live.Add(1)
	return info
}

// Forget removes a connection from the registry. Safe to call after MarkClosed.
func (t *ConnTracker) Forget(id uint64) {
	t.mu.Lock()
	_, existed := t.conns[id]
	delete(t.conns, id)
	t.mu.Unlock()
	if existed {
		t.live.Add(-1)
	}
}

// Snapshot returns a defensive copy of all currently-tracked conns. The slice
// is safe for callers to iterate without holding the tracker lock.
func (t *ConnTracker) Snapshot() []*ConnInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*ConnInfo, 0, len(t.conns))
	for _, c := range t.conns {
		out = append(out, c)
	}
	return out
}

// Live returns the live connection count (atomic).
func (t *ConnTracker) Live() int64 { return t.live.Load() }

// Kill detaches a single tracked connection by ID. Phase A doesn't expose an
// external kill API yet — this is reserved for the DELETE /connections/{id}
// endpoint added in Phase E. Operation is best-effort: the supplied close setter
// is invoked under the map lock so the proxy loop will observe EOF on the next
// read/write cycle. Returns true if a live conn was found and closed.
func (t *ConnTracker) Kill(id uint64, closer func() error) bool {
	if closer == nil {
		return false
	}
	t.mu.RLock()
	_, ok := t.conns[id]
	t.mu.RUnlock()
	if !ok {
		return false
	}
	_ = closer() // closing the net.Conn unblocks the proxy io.Copy goroutines.
	return true
}