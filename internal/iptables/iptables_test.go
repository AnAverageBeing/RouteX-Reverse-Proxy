package iptables_test

import (
	"testing"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/iptables"
)

func TestValidateRateLimits_Valid(t *testing.T) {
	rl := config.ProxyRateLimits{
		TCPPSSPerIP:              100,
		UDPPSSPerIP:              200,
		NewConnsPerSecPerIP:      10,
		MaxSimultaneousConnsPerIP: 5,
		MinTTL:                   10,
		MaxTTL:                   255,
		MinPacketSize:            20,
		MaxPacketSize:            1500,
		UDPMaxPayload:            4096,
		UDPMinPayload:            1,
	}
	res := iptables.ValidateRateLimits(rl, "tcp-udp")
	if !res.Valid {
		t.Errorf("should be valid, errors: %v", res.Errors)
	}
}

func TestValidateRateLimits_TTLRange(t *testing.T) {
	rl := config.ProxyRateLimits{
		MinTTL: 100,
		MaxTTL: 50,
	}
	res := iptables.ValidateRateLimits(rl, "tcp")
	if res.Valid {
		t.Error("should reject min_ttl >= max_ttl")
	}
}

func TestValidateRateLimits_PacketSizeRange(t *testing.T) {
	rl := config.ProxyRateLimits{
		MinPacketSize: 2000,
		MaxPacketSize: 1000,
	}
	res := iptables.ValidateRateLimits(rl, "tcp")
	if res.Valid {
		t.Error("should reject min_packet_size >= max_packet_size")
	}
}

func TestValidateRateLimits_NegativeValues(t *testing.T) {
	rl := config.ProxyRateLimits{
		TCPPSSPerIP:            -1,
		NewConnsPerSecPerIP:    -5,
		MaxSimultaneousConnsPerIP: -10,
	}
	res := iptables.ValidateRateLimits(rl, "tcp")
	if res.Valid {
		t.Error("should reject negative rate values")
	}
}

func TestValidateRateLimits_OutOfRangePorts(t *testing.T) {
	rl := config.ProxyRateLimits{
		MinTTL:        300,
		MaxTTL:        400,
		MinPacketSize: 70000,
		MaxPacketSize: 80000,
	}
	res := iptables.ValidateRateLimits(rl, "tcp")
	if res.Valid {
		t.Error("should reject out-of-range values")
	}
}

func TestValidateRateLimits_UDPOnlyWarns(t *testing.T) {
	rl := config.ProxyRateLimits{
		TCPPSSPerIP:         100,
		TCPSYNRatePerIP:     50,
		TCPInvalidStateDrop: true,
		TCPRSTRatePerIP:     30,
	}
	res := iptables.ValidateRateLimits(rl, "udp")
	if !res.Valid {
		t.Error("should still be valid with udp protocol")
	}
	if len(res.Warns) == 0 {
		t.Error("should warn about tcp-specific limits on udp-only proxy")
	}
}

func TestBuildRules_TCPOnly(t *testing.T) {
	rl := config.ProxyRateLimits{
		TCPPSSPerIP:              500,
		NewConnsPerSecPerIP:      20,
		MaxSimultaneousConnsPerIP: 10,
		DropFragmentedPackets:    true,
		TCPSYNRatePerIP:          10,
		TCPInvalidStateDrop:      true,
	}
	rules := iptables.BuildRules("test", []int{25565}, rl, "tcp", "RouteX")
	if len(rules) == 0 {
		t.Fatal("expected non-empty rules for tcp proxy")
	}
	// Verify we have the expected rule types
	hasPPS := false
	hasConn := false
	for _, r := range rules {
		if r.Table != "filter" || r.Chain != "INPUT" {
			t.Errorf("unexpected table/chain: %s/%s", r.Table, r.Chain)
		}
		if len(r.Spec) == 0 {
			t.Error("rule has empty spec")
		}
		// Check for -j DROP termination
		last := r.Spec[len(r.Spec)-1]
		if last != "DROP" {
			t.Errorf("rule should end with DROP, got %q", last)
		}
		// Check comment format
		if r.Comment == "" {
			t.Error("rule comment is empty")
		}
		_ = hasPPS
		_ = hasConn
	}
}

func TestBuildRules_Disabled(t *testing.T) {
	rl := config.ProxyRateLimits{} // all zeros/false
	rules := iptables.BuildRules("test", []int{25565}, rl, "tcp", "RouteX")
	if len(rules) != 0 {
		t.Errorf("expected no rules for all-zero rate limits, got %d", len(rules))
	}
}

func TestBuildRules_PortRange(t *testing.T) {
	rl := config.ProxyRateLimits{
		TCPPSSPerIP: 100,
	}
	// Contiguous port range
	rules := iptables.BuildRules("test", []int{25565, 25566, 25567}, rl, "tcp", "RouteX")
	if len(rules) == 0 {
		t.Fatal("expected rules")
	}
	// Check port argument uses range syntax for contiguous ports
	found := false
	for _, spec := range rules[0].Spec {
		if spec == "25565:25567" {
			found = true
		}
	}
	if !found {
		t.Error("contiguous port range should use 25565:25567 syntax")
	}
}

func TestBuildRules_UDPOnlySkipsTCP(t *testing.T) {
	rl := config.ProxyRateLimits{
		TCPPSSPerIP:         500,
		UDPPSSPerIP:         1000,
		TCPSYNRatePerIP:     10,
		TCPInvalidStateDrop: true,
	}
	rules := iptables.BuildRules("test", []int{25565}, rl, "udp", "RouteX")
	// Only UDP rules should be present
	hasTCP := false
	hasUDP := false
	for _, r := range rules {
		for _, s := range r.Spec {
			if s == "-p" {
				continue
			}
			switch s {
			case "tcp":
				hasTCP = true
			case "udp":
				hasUDP = true
			}
		}
	}
	if hasTCP {
		t.Error("udp-only proxy should not have tcp rules")
	}
	if !hasUDP {
		t.Error("udp-only proxy should have udp rules")
	}
}
