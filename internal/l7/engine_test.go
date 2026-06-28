package l7_test

import (
	"net"
	"testing"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/l7"
)

func TestEngine_OnAccept_BanCheck(t *testing.T) {
	cfg := config.ProxyL7Protection{Enabled: true}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("5.5.5.5")
	// Ban the IP
	eng.BanIP(ip, time.Hour, "test ban")

	if !eng.IsBanned(ip) {
		t.Fatal("IP should be banned")
	}
	if eng.OnAccept(ip) {
		t.Error("banned IP should be rejected")
	}
}

func TestEngine_OnAccept_ConnectionCycling(t *testing.T) {
	cfg := config.ProxyL7Protection{
		Enabled: true,
		ConnectionCycling: config.ProxyL7ConnectionCycling{
			Enabled:          true,
			Window:           config.Duration(10 * time.Second),
			MaxConnsInWindow: 5,
			BanDuration:      config.Duration(60 * time.Second),
		},
	}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("6.6.6.6")
	// First 5 should pass
	for i := 0; i < 5; i++ {
		if !eng.OnAccept(ip) {
			t.Errorf("connection %d should be accepted", i+1)
		}
	}
	// 6th should be blocked (cycling detection)
	if eng.OnAccept(ip) {
		t.Error("6th connection should be blocked by cycling detection")
	}
}

func TestEngine_OnData_PayloadInspection(t *testing.T) {
	cfg := config.ProxyL7Protection{
		Enabled: true,
		PayloadInspection: config.ProxyL7PayloadInspection{
			Enabled: true,
			Mode:    "minecraft-java",
		},
	}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("7.7.7.7")

	// Valid Minecraft handshake
	validPayload := []byte{
		0x10, 0x00, 0xF2, 0x05,
		0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0x63, 0xDD, 0x02,
	}
	inspected := false
	if !eng.OnData(ip, validPayload, &inspected) {
		t.Error("valid Minecraft payload should pass inspection")
	}

	// Bad payload
	badPayload := []byte{0xFF, 0xFF, 0xFF}
	inspected = false
	if eng.OnData(ip, badPayload, &inspected) {
		t.Error("invalid payload should be blocked")
	}
}

func TestEngine_OnData_PayloadRateLimit(t *testing.T) {
	cfg := config.ProxyL7Protection{
		Enabled: true,
		PayloadRateLimit: config.ProxyL7PayloadRateLimit{
			Enabled:               true,
			MaxBytesPerSecPerIP:   100,
			BurstMultiplier:       1.0,
		},
	}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("8.8.8.8")
	inspected := true // skip inspection

	payload := make([]byte, 50)
	// First two should pass (50 * 2 = 100 bytes)
	if !eng.OnData(ip, payload, &inspected) {
		t.Error("first 50 bytes should pass")
	}
	if !eng.OnData(ip, payload, &inspected) {
		t.Error("second 50 bytes should pass")
	}
	// Third should hit the rate limit
	if eng.OnData(ip, payload, &inspected) {
		t.Error("third 50 bytes should be rate limited")
	}
}

func TestEngine_BehavioralScoring(t *testing.T) {
	cfg := config.ProxyL7Protection{
		Enabled: true,
		PayloadInspection: config.ProxyL7PayloadInspection{
			Enabled: true,
			Mode:    "minecraft-java",
		},
		BehavioralScoring: config.ProxyL7BehavioralScoring{
			Enabled:      true,
			ScoreWindow:  config.Duration(30 * time.Second),
			BanThreshold: 50,
			BanDuration:  config.Duration(10 * time.Second),
			ScoreRules: []config.ProxyL7BehavioralScoreRule{
				{Event: "invalid_protocol", Score: 30},
			},
		},
	}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("9.9.9.9")

	// First bad payload: score 30 (below threshold of 50)
	badPayload := []byte{0xFF, 0xFF, 0xFF}
	inspected := false
	if eng.OnData(ip, badPayload, &inspected) {
		t.Error("bad payload should be blocked")
	}
	if eng.IsBanned(ip) {
		t.Error("IP should NOT be banned at score 30 (threshold 50)")
	}

	// Second bad payload: score 60 (above threshold 50) → ban
	inspected = false
	_ = eng.OnData(ip, badPayload, &inspected)
	if !eng.IsBanned(ip) {
		t.Error("IP SHOULD be banned after score 60 (above threshold 50)")
	}
}

func TestEngine_Unban(t *testing.T) {
	cfg := config.ProxyL7Protection{Enabled: true}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("10.10.10.10")
	eng.BanIP(ip, time.Hour, "test")
	if !eng.IsBanned(ip) {
		t.Fatal("should be banned")
	}
	eng.UnbanIP(ip)
	if eng.IsBanned(ip) {
		t.Fatal("should be unbanned")
	}
}

func TestEngine_Disabled(t *testing.T) {
	cfg := config.ProxyL7Protection{Enabled: false}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("11.11.11.11")
	// Everything should pass when disabled
	if !eng.OnAccept(ip) {
		t.Error("OnAccept should pass when disabled")
	}
	inspected := false
	if !eng.OnData(ip, []byte{0xFF}, &inspected) {
		t.Error("OnData should pass when disabled")
	}
	if eng.BlockedConns() != 0 {
		t.Error("no blocks when disabled")
	}
}

func TestEngine_Events(t *testing.T) {
	cfg := config.ProxyL7Protection{
		Enabled: true,
		ConnectionCycling: config.ProxyL7ConnectionCycling{
			Enabled:          true,
			Window:           config.Duration(10 * time.Second),
			MaxConnsInWindow: 1,
			BanDuration:      config.Duration(60 * time.Second),
		},
	}
	eng := l7.NewEngine(cfg)

	ip := net.ParseIP("12.12.12.12")
	eng.OnAccept(ip) // pass
	eng.OnAccept(ip) // blocked (cycling)

	events := eng.Events(10)
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	found := false
	for _, e := range events {
		if e.EventType == "connection_cycling" {
			found = true
			if e.Action != "blocked" {
				t.Errorf("action = %q, want blocked", e.Action)
			}
		}
	}
	if !found {
		t.Error("connection_cycling event not found")
	}
}

func TestEngine_BannedList(t *testing.T) {
	eng := l7.NewEngine(config.ProxyL7Protection{Enabled: true})
	ip1 := net.ParseIP("1.1.1.1")
	ip2 := net.ParseIP("2.2.2.2")

	eng.BanIP(ip1, time.Hour, "reason1")
	eng.BanIP(ip2, time.Hour, "reason2")

	list := eng.BannedList()
	if len(list) != 2 {
		t.Fatalf("banned list length = %d, want 2", len(list))
	}
}
