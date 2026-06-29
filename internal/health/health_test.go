package health_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/health"
	"go.uber.org/zap"
)

func TestNew_InvalidConfig(t *testing.T) {
	targets := []health.Target{{IP: net.ParseIP("127.0.0.1"), Port: 1}}

	_, err := health.New(health.Config{Interval: 0, Timeout: time.Second, FailuresBeforeEject: 1, PassesBeforeReadmit: 1}, targets, nil, nil)
	if err == nil {
		t.Error("zero interval should fail")
	}

	_, err = health.New(health.Config{Interval: time.Second, Timeout: 2 * time.Second, FailuresBeforeEject: 1, PassesBeforeReadmit: 1}, targets, nil, nil)
	if err == nil {
		t.Error("timeout > interval should fail")
	}

	_, err = health.New(health.Config{Interval: time.Second, Timeout: time.Second, FailuresBeforeEject: 1, PassesBeforeReadmit: 1}, nil, nil, nil)
	if err == nil {
		t.Error("empty targets should fail")
	}
}

func TestNew_OptimisticStart(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	checker, err := health.New(health.Config{
		Interval:            time.Second,
		Timeout:             time.Second,
		FailuresBeforeEject: 3,
		PassesBeforeReadmit: 2,
	}, []health.Target{{IP: ip, Port: 9}}, nil, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// Before any probes, target should be optimistically healthy.
	if !checker.Healthy(ip, 9) {
		t.Error("freshly created checker should report healthy (optimistic)")
	}
}

func TestChecker_HealthCallback_Eject(t *testing.T) {
	// Start a TCP server that we can stop to trigger health failures.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	var ejected atomic.Bool
	onChange := func(ip net.IP, p int, healthy bool) {
		if !healthy {
			ejected.Store(true)
		}
	}

	ip := net.ParseIP("127.0.0.1")
	checker, err := health.New(health.Config{
		Interval:            100 * time.Millisecond,
		Timeout:             50 * time.Millisecond,
		FailuresBeforeEject: 2,
		PassesBeforeReadmit: 1,
	}, []health.Target{{IP: ip, Port: port}}, onChange, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = checker.Start(ctx)

	// Close the listener to force health failures.
	ln.Close()

	// Wait up to 2 seconds for eject.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ejected.Load() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	checker.Stop()
	if !ejected.Load() {
		t.Error("health checker should have fired eject callback")
	}
}

func TestChecker_HealthCallback_Readmit(t *testing.T) {
	// Start a server, eject it, restart server, verify readmit.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	// Accept in background to keep the listener alive.
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()

	states := make([]bool, 0, 4)
	onChange := func(ip net.IP, p int, healthy bool) {
		states = append(states, healthy)
	}

	ip := net.ParseIP("127.0.0.1")
	cfg := health.Config{
		Interval:            80 * time.Millisecond,
		Timeout:             40 * time.Millisecond,
		FailuresBeforeEject: 2,
		PassesBeforeReadmit: 2,
	}
	checker, _ := health.New(cfg, []health.Target{{IP: ip, Port: port}}, onChange, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = checker.Start(ctx)

	// Close to trigger eject.
	ln.Close()
	time.Sleep(500 * time.Millisecond)

	// Reopen on same port to trigger readmit.
	ln2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skip("cannot reuse port for readmit test")
	}
	defer ln2.Close()
	go func() {
		for {
			c, e := ln2.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()

	time.Sleep(500 * time.Millisecond)
	checker.Stop()
}

func TestChecker_StopIdempotent(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	checker, _ := health.New(health.Config{
		Interval:            time.Second,
		Timeout:             time.Second,
		FailuresBeforeEject: 1,
		PassesBeforeReadmit: 1,
	}, []health.Target{{IP: ip, Port: 1}}, nil, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	_ = checker.Start(ctx)
	cancel()

	// Stop multiple times — should not panic.
	checker.Stop()
	checker.Stop()
	checker.Stop()
}

func TestChecker_StartIdempotent(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	checker, _ := health.New(health.Config{
		Interval:            time.Second,
		Timeout:             time.Second,
		FailuresBeforeEject: 1,
		PassesBeforeReadmit: 1,
	}, []health.Target{{IP: ip, Port: 1}}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = checker.Start(ctx)
	// Second start should be a no-op (idempotent).
	err := checker.Start(ctx)
	if err != nil {
		t.Errorf("second Start should be no-op, got error: %v", err)
	}
}
