package lb_test

import (
	"net"
	"sync"
	"testing"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/lb"
)

func makeTargets(n int) []*lb.Target {
	out := make([]*lb.Target, n)
	for i := 0; i < n; i++ {
		out[i] = lb.NewTarget(net.ParseIP("10.0.0.1"), 8000+i, 1, true)
	}
	return out
}

func TestRoundRobin(t *testing.T) {
	targets := makeTargets(3)
	b, err := lb.New("round-robin", targets, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	src := net.ParseIP("1.1.1.1")
	picks := make(map[int]int)
	for i := 0; i < 90; i++ {
		tgt, err := b.Pick(src)
		if err != nil {
			t.Fatal(err)
		}
		picks[tgt.Port]++
		b.Release(tgt)
	}

	for port, count := range picks {
		if count < 25 || count > 35 {
			t.Errorf("port %d got %d picks, expected ~30 (fair distribution)", port, count)
		}
	}
}

func TestLeastConn(t *testing.T) {
	targets := makeTargets(3)
	b, err := lb.New("least-conn", targets, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	src := net.ParseIP("1.1.1.1")
	// Hold one connection open to port 8000
	held, err := b.Pick(src)
	if err != nil {
		t.Fatal(err)
	}
	if held.Port != 8000 {
		t.Errorf("first pick = %d, want 8000 (first target with min conns)", held.Port)
	}
	// Next picks should avoid the held target since it has active conns
	next, err := b.Pick(src)
	if err != nil {
		t.Fatal(err)
	}
	if next.Port == held.Port {
		t.Error("second pick should avoid target with active connection")
	}
	b.Release(held)
	b.Release(next)
}

func TestIPHash(t *testing.T) {
	targets := makeTargets(5)
	b, err := lb.New("ip-hash", targets, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Same IP should map to same target
	ip := net.ParseIP("192.168.1.100")
	first, err := b.Pick(ip)
	if err != nil {
		t.Fatal(err)
	}
	b.Release(first)

	for i := 0; i < 20; i++ {
		tgt, err := b.Pick(ip)
		if err != nil {
			t.Fatal(err)
		}
		if tgt.Port != first.Port {
			t.Errorf("ip-hash inconsistent: first=%d, pick[%d]=%d", first.Port, i, tgt.Port)
		}
		b.Release(tgt)
	}

	// Different IP may map differently
	ip2 := net.ParseIP("10.0.0.99")
	second, err := b.Pick(ip2)
	if err != nil {
		t.Fatal(err)
	}
	b.Release(second)
}

func TestWeighted(t *testing.T) {
	t1 := lb.NewTarget(net.ParseIP("10.0.0.1"), 8000, 10, true)
	t2 := lb.NewTarget(net.ParseIP("10.0.0.2"), 9000, 1, true)
	b, err := lb.New("weighted", []*lb.Target{t1, t2}, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	src := net.ParseIP("1.1.1.1")
	picks := map[int]int{}
	for i := 0; i < 1100; i++ {
		tgt, err := b.Pick(src)
		if err != nil {
			t.Fatal(err)
		}
		picks[tgt.Port]++
		b.Release(tgt)
	}

	// Weight 10 vs 1 → roughly 10:1 ratio
	r8000 := picks[8000]
	r9000 := picks[9000]
	t.Logf("weighted distribution: 8000=%d, 9000=%d", r8000, r9000)
	if r8000 < r9000 {
		t.Errorf("weight 10 target (8000) should get more picks than weight 1 target (9000): %d vs %d", r8000, r9000)
	}
}

func TestRandom(t *testing.T) {
	targets := makeTargets(4)
	b, err := lb.New("random", targets, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	src := net.ParseIP("1.1.1.1")
	picks := map[int]int{}
	for i := 0; i < 1000; i++ {
		tgt, err := b.Pick(src)
		if err != nil {
			t.Fatal(err)
		}
		picks[tgt.Port]++
		b.Release(tgt)
	}

	for _, count := range picks {
		if count < 150 || count > 350 {
			t.Errorf("random distribution: count %d outside expected range [150,350]", count)
		}
	}
}

func TestHealthAwarePicking(t *testing.T) {
	t1 := lb.NewTarget(net.ParseIP("10.0.0.1"), 8000, 1, true)
	t2 := lb.NewTarget(net.ParseIP("10.0.0.2"), 9000, 1, true)
	t3 := lb.NewTarget(net.ParseIP("10.0.0.3"), 7000, 1, true)
	b, _ := lb.New("round-robin", []*lb.Target{t1, t2, t3}, false, 0)

	// Mark t1 and t2 unhealthy
	b.SetHealth(net.ParseIP("10.0.0.1"), 8000, false)
	b.SetHealth(net.ParseIP("10.0.0.2"), 9000, false)

	src := net.ParseIP("1.1.1.1")
	for i := 0; i < 10; i++ {
		tgt, err := b.Pick(src)
		if err != nil {
			t.Fatal(err)
		}
		if tgt.Port != 7000 {
			t.Errorf("expected only healthy target 7000, got %d", tgt.Port)
		}
		b.Release(tgt)
	}

	// All unhealthy -> error
	b.SetHealth(net.ParseIP("10.0.0.3"), 7000, false)
	_, err := b.Pick(src)
	if err == nil {
		t.Fatal("expected ErrNoHealthyTargets when all targets unhealthy")
	}
}

func TestStickySessions(t *testing.T) {
	targets := makeTargets(3)
	b, err := lb.New("round-robin", targets, true, 3600)
	if err != nil {
		t.Fatal(err)
	}

	src := net.ParseIP("1.2.3.4")
	first, err := b.Pick(src)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		// Release to keep active conns at zero (sticky should still work)
		b.Release(first)
		tgt, err := b.Pick(src)
		if err != nil {
			t.Fatal(err)
		}
		if tgt.Port != first.Port {
			t.Errorf("sticky session broken: expected %d, got %d at pick %d", first.Port, tgt.Port, i)
		}
		b.Release(tgt)
	}
}

func TestSnapshot(t *testing.T) {
	targets := makeTargets(3)
	b, _ := lb.New("round-robin", targets, false, 0)
	snap := b.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot length = %d, want 3", len(snap))
	}
	for _, s := range snap {
		if !s.Healthy {
			t.Errorf("target %s:%d should be healthy", s.IP, s.Port)
		}
	}
}

func TestConcurrentPicking(t *testing.T) {
	targets := makeTargets(10)
	b, _ := lb.New("least-conn", targets, false, 0)
	src := net.ParseIP("10.1.1.1")

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tgt, err := b.Pick(src)
				if err != nil {
					errs <- err
					return
				}
				b.Release(tgt)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
