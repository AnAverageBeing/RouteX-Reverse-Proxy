package metrics

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

type Store struct {
	db    *sql.DB
	mu    sync.RWMutex
	cache map[string]*ProxyMetrics
	global GlobalMetrics

	flushInterval time.Duration
	retention     time.Duration
	logger        *zap.Logger

	closed uint32
	stop   chan struct{}
}

type GlobalMetrics struct {
	TotalConnections   int64
	ActiveConnections  int64
	TotalBytesIn       int64
	TotalBytesOut      int64
	ConfigReloadCount  int64
	ConfigReloadErrors int64
	ConfigReloadLastTS int64
}

type ProxyMetrics struct {
	Name                 string
	ActiveConnections    int64
	TotalConnections     int64
	BytesIn              int64
	BytesOut             int64
	L7BlockedConnections int64
	L7BannedIPs          int64
	IptablesRulesActive  int64
	RateLimitedDrops     int64
	Upstreams            map[string]*UpstreamMetrics
}

type UpstreamMetrics struct {
	IP          string
	Port        int
	ActiveConns int64
	TotalConns  int64
	TotalBytes  int64
	Healthy     int64
	FailCount   int64
}

func NewStore(dbPath string, flushInterval, retention time.Duration, logger *zap.Logger) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("metrics: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{
		db:            db,
		cache:         make(map[string]*ProxyMetrics),
		flushInterval: flushInterval,
		retention:     retention,
		logger:        logger,
		stop:          make(chan struct{}),
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("metrics: migrate: %w", err)
	}

	go s.flushLoop()
	return s, nil
}

func (s *Store) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS proxy_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			proxy_name TEXT NOT NULL,
			timestamp INTEGER NOT NULL,
			active_connections INTEGER,
			total_connections INTEGER,
			bytes_in INTEGER,
			bytes_out INTEGER,
			l7_blocked INTEGER,
			l7_banned INTEGER,
			iptables_rules_active INTEGER,
			rate_limited_drops INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pm_name_time ON proxy_metrics(proxy_name, timestamp)`,
		`CREATE TABLE IF NOT EXISTS upstream_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			proxy_name TEXT NOT NULL,
			upstream_ip TEXT NOT NULL,
			upstream_port INTEGER NOT NULL,
			timestamp INTEGER NOT NULL,
			active_conns INTEGER,
			total_conns INTEGER,
			total_bytes INTEGER,
			healthy INTEGER,
			fail_count INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_um_name_time ON upstream_metrics(proxy_name, timestamp)`,
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Get(name string) *ProxyMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cache[name]
}

func (s *Store) Set(name string, update func(m *ProxyMetrics)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.cache[name]
	if !ok {
		m = &ProxyMetrics{Name: name, Upstreams: make(map[string]*UpstreamMetrics)}
		s.cache[name] = m
	}
	update(m)
}

func (s *Store) UpdateGlobal(fn func(g *GlobalMetrics)) {
	s.mu.Lock()
	fn(&s.global)
	s.mu.Unlock()
}

func (s *Store) All() map[string]*ProxyMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ProxyMetrics, len(s.cache))
	for k, v := range s.cache {
		out[k] = v
	}
	return out
}

func (s *Store) GlobalSnapshot() GlobalMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.global
}

func (s *Store) Close() error {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}
	close(s.stop)
	s.flushAll()
	return s.db.Close()
}

func (s *Store) flushLoop() {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.flushAll()
		}
	}
}

func (s *Store) flushAll() {
	s.mu.RLock()
	cache := make(map[string]*ProxyMetrics, len(s.cache))
	for k, v := range s.cache {
		cache[k] = v
	}
	s.mu.RUnlock()

	now := time.Now().Unix()
	for name, m := range cache {
		_, _ = s.db.Exec(
			`INSERT INTO proxy_metrics (proxy_name, timestamp, active_connections, total_connections,
			 bytes_in, bytes_out, l7_blocked, l7_banned, iptables_rules_active, rate_limited_drops)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			name, now,
			atomic.LoadInt64(&m.ActiveConnections),
			atomic.LoadInt64(&m.TotalConnections),
			atomic.LoadInt64(&m.BytesIn),
			atomic.LoadInt64(&m.BytesOut),
			atomic.LoadInt64(&m.L7BlockedConnections),
			atomic.LoadInt64(&m.L7BannedIPs),
			atomic.LoadInt64(&m.IptablesRulesActive),
			atomic.LoadInt64(&m.RateLimitedDrops),
		)
		for _, u := range m.Upstreams {
			_, _ = s.db.Exec(
				`INSERT INTO upstream_metrics (proxy_name, upstream_ip, upstream_port, timestamp,
				 active_conns, total_conns, total_bytes, healthy, fail_count)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				name, u.IP, u.Port, now,
				atomic.LoadInt64(&u.ActiveConns),
				atomic.LoadInt64(&u.TotalConns),
				atomic.LoadInt64(&u.TotalBytes),
				atomic.LoadInt64(&u.Healthy),
				atomic.LoadInt64(&u.FailCount),
			)
		}
	}

	cutoff := time.Now().Add(-s.retention).Unix()
	_, _ = s.db.Exec(`DELETE FROM proxy_metrics WHERE timestamp < ?`, cutoff)
	_, _ = s.db.Exec(`DELETE FROM upstream_metrics WHERE timestamp < ?`, cutoff)
}
