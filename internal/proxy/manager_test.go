package proxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/acl"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/proxy"
	"go.uber.org/zap"
)

// idEchoServer answers each connection with "B<port>\n" then echoes input.
// The greeting lets tests identify which backend served a connection.
func idEchoServer(t *testing.T, port int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("backend listen %d: %v", port, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fmt.Fprintf(conn, "B%d\n", port)
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						conn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func testGlobal() *config.Global {
	g := &config.Global{}
	g.Defaults.UpstreamConnectTimeout = config.Duration(2 * time.Second)
	g.Defaults.UpstreamReadTimeout = config.Duration(5 * time.Second)
	g.Defaults.UpstreamWriteTimeout = config.Duration(5 * time.Second)
	g.Defaults.ClientReadTimeout = config.Duration(5 * time.Second)
	g.Defaults.ClientWriteTimeout = config.Duration(5 * time.Second)
	g.Defaults.HealthCheckInterval = config.Duration(2 * time.Second)
	g.Defaults.HealthCheckTimeout = config.Duration(1 * time.Second)
	g.Defaults.HealthCheckFailuresBeforeEject = 2
	g.Defaults.HealthCheckPassesBeforeReadmit = 1
	g.Defaults.UDPSessionTimeout = config.Duration(2 * time.Second)
	g.Network.TCPNoDelay = true
	return g
}

// installACLHook wires per-proxy ACL construction the same way cmd/routex does:
// the manager's onInstanceStart hook builds the engine from config and registers
// it. This is the path that previously deadlocked and silently dropped ACLs.
func installACLHook(mgr *proxy.Manager) {
	mgr.SetHooks(func(inst *proxy.Instance) {
		c := inst.Config.ACL
		if c.DefaultAction == "" && len(c.Rules) == 0 {
			return
		}
		da := acl.Action(c.DefaultAction)
		if da == "" {
			da = acl.Allow
		}
		rules := make([]acl.Rule, 0, len(c.Rules))
		for _, r := range c.Rules {
			rules = append(rules, acl.Rule{Action: acl.Action(r.Action), CIDR: r.CIDR, Comment: r.Comment})
		}
		if eng, err := acl.NewEngine(inst.Name, da, rules, true); err == nil {
			mgr.SetProxyACL(inst.Name, eng)
		}
	}, func(inst *proxy.Instance) {})
}

func dialGreet(t *testing.T, addr string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	g, err := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(g), err
}

// TestManagerStart_NoDeadlock guards the self-deadlock regression: Manager.Start
// used to hold m.mu while buildInstance re-acquired it via getComposedACL,
// permanently hanging on the very first proxy. It must complete promptly.
func TestManagerStart_NoDeadlock(t *testing.T) {
	backendPort := freePort(t)
	ln := idEchoServer(t, backendPort)
	defer ln.Close()

	originPort := freePort(t)
	p := &config.Proxy{
		Name:       "deadlock-guard",
		Enabled:    true,
		OriginIP:   "127.0.0.1",
		OriginPort: fmt.Sprintf("%d", originPort),
		DestIP:     "127.0.0.1",
		DestPort:   fmt.Sprintf("%d", backendPort),
		Protocol:   "tcp",
	}
	p.LoadBalancing.Algorithm = "round-robin"
	// A non-empty ACL forces the composed-ACL path that triggered the deadlock.
	p.ACL.DefaultAction = "allow"
	p.ACL.Rules = []config.ProxyACLRule{{Action: "deny", CIDR: "203.0.113.7/32"}}

	mgr := proxy.NewManager(testGlobal(), zap.NewNop())
	installACLHook(mgr)

	done := make(chan error, 1)
	go func() { done <- mgr.Start(p) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Manager.Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Manager.Start deadlocked (did not return within 5s)")
	}
	defer mgr.StopAll()

	// Traffic from 127.0.0.1 is allowed (deny rule targets a different IP).
	time.Sleep(100 * time.Millisecond)
	got, err := dialGreet(t, fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		t.Fatalf("expected traffic to flow, got err: %v", err)
	}
	if got != fmt.Sprintf("B%d", backendPort) {
		t.Fatalf("unexpected backend greeting %q", got)
	}
}

// TestManagerStart_PerProxyACLApplies proves the per-proxy ACL registered by the
// onInstanceStart hook is actually enforced on live connections — previously the
// proxy snapshotted a nil ACL at build time and the rule never took effect.
func TestManagerStart_PerProxyACLApplies(t *testing.T) {
	backendPort := freePort(t)
	ln := idEchoServer(t, backendPort)
	defer ln.Close()

	originPort := freePort(t)
	p := &config.Proxy{
		Name:       "acl-applies",
		Enabled:    true,
		OriginIP:   "127.0.0.1",
		OriginPort: fmt.Sprintf("%d", originPort),
		DestIP:     "127.0.0.1",
		DestPort:   fmt.Sprintf("%d", backendPort),
		Protocol:   "tcp",
	}
	p.LoadBalancing.Algorithm = "round-robin"
	p.ACL.DefaultAction = "allow"
	p.ACL.Rules = []config.ProxyACLRule{{Action: "deny", CIDR: "127.0.0.1/32"}}

	mgr := proxy.NewManager(testGlobal(), zap.NewNop())
	installACLHook(mgr)
	if err := mgr.Start(p); err != nil {
		t.Fatalf("Manager.Start: %v", err)
	}
	defer mgr.StopAll()

	time.Sleep(100 * time.Millisecond)
	// The deny rule covers 127.0.0.1, so the connection must be closed with no data.
	got, err := dialGreet(t, fmt.Sprintf("127.0.0.1:%d", originPort))
	if err == nil && got != "" {
		t.Fatalf("expected ACL to deny localhost, but got greeting %q", got)
	}
}

// TestManagerStart_FanOutLB verifies fan-out load balancing spreads connections
// across all dest ports. The earlier bug pinned every connection to the first
// dest port because the resolver port was used instead of the balancer's choice.
func TestManagerStart_FanOutLB(t *testing.T) {
	ports := []int{freePort(t), freePort(t), freePort(t)}
	for _, bp := range ports {
		ln := idEchoServer(t, bp)
		defer ln.Close()
	}
	originPort := freePort(t)
	p := &config.Proxy{
		Name:       "fanout-lb",
		Enabled:    true,
		OriginIP:   "127.0.0.1",
		OriginPort: fmt.Sprintf("%d", originPort),
		DestIP:     "127.0.0.1",
		DestPort:   fmt.Sprintf("%d, %d, %d", ports[0], ports[1], ports[2]),
		Protocol:   "tcp",
		OneToOne:   false,
	}
	p.LoadBalancing.Algorithm = "round-robin"

	mgr := proxy.NewManager(testGlobal(), zap.NewNop())
	mgr.SetHooks(func(*proxy.Instance) {}, func(*proxy.Instance) {})
	if err := mgr.Start(p); err != nil {
		t.Fatalf("Manager.Start: %v", err)
	}
	defer mgr.StopAll()

	time.Sleep(100 * time.Millisecond)
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		got, err := dialGreet(t, fmt.Sprintf("127.0.0.1:%d", originPort))
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		seen[got]++
		time.Sleep(10 * time.Millisecond)
	}
	if len(seen) != 3 {
		t.Fatalf("fan-out LB did not spread across 3 backends: %v", seen)
	}
}
