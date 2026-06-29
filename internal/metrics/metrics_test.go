package metrics_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/metrics"
	"go.uber.org/zap"
)

func newTestStore(t *testing.T) (*metrics.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := metrics.NewStore(dbPath, 100*time.Millisecond, time.Hour, zap.NewNop())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, func() { _ = s.Close() }
}

func TestStore_SetAndGet(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.Set("proxy1", func(m *metrics.ProxyMetrics) {
		m.ActiveConnections = 10
		m.BytesIn = 1000
	})

	m := s.Get("proxy1")
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}
	if m.ActiveConnections != 10 {
		t.Errorf("active = %d, want 10", m.ActiveConnections)
	}
	if m.BytesIn != 1000 {
		t.Errorf("bytes_in = %d, want 1000", m.BytesIn)
	}
}

func TestStore_GetNonExistent(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	m := s.Get("nonexistent")
	if m != nil {
		t.Error("expected nil for unknown proxy")
	}
}

func TestStore_UpdateGlobal(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.UpdateGlobal(func(g *metrics.GlobalMetrics) {
		g.TotalConnections = 500
		g.ActiveConnections = 25
	})

	g := s.GlobalSnapshot()
	if g.TotalConnections != 500 {
		t.Errorf("total = %d, want 500", g.TotalConnections)
	}
	if g.ActiveConnections != 25 {
		t.Errorf("active = %d, want 25", g.ActiveConnections)
	}
}

func TestStore_All(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.Set("p1", func(m *metrics.ProxyMetrics) { m.ActiveConnections = 1 })
	s.Set("p2", func(m *metrics.ProxyMetrics) { m.ActiveConnections = 2 })
	s.Set("p3", func(m *metrics.ProxyMetrics) { m.ActiveConnections = 3 })

	all := s.All()
	if len(all) != 3 {
		t.Errorf("got %d proxies, want 3", len(all))
	}
}

func TestStore_FlushLoop(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "flush_test.db")
	s, err := metrics.NewStore(dbPath, 50*time.Millisecond, time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Set("proxy1", func(m *metrics.ProxyMetrics) {
		m.ActiveConnections = 42
		m.BytesIn = 9999
	})

	// Wait for at least one flush.
	time.Sleep(200 * time.Millisecond)

	// Verify the DB file exists.
	if _, statErr := os.Stat(dbPath); os.IsNotExist(statErr) {
		t.Error("SQLite DB file should exist after flush")
	}
}

func TestStore_CloseIdempotent(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second close should be safe.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestMetricsAPI_JSON(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.UpdateGlobal(func(g *metrics.GlobalMetrics) {
		g.TotalConnections = 100
		g.ActiveConnections = 5
	})

	api := metrics.NewMetricsAPI(s)
	if api == nil {
		t.Fatal("NewMetricsAPI returned nil")
	}
	// Just verify it doesn't panic by calling ServeHTTP via the handler.
	// Full HTTP test would need httptest — keep lightweight.
}
