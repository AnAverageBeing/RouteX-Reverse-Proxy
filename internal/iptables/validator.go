package iptables

import (
	"fmt"
	"os/exec"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
)

type ValidateResult struct {
	Valid  bool
	Errors []string
	Warns  []string
}

func ValidateRateLimits(rl config.ProxyRateLimits, protocol string) ValidateResult {
	res := ValidateResult{Valid: true}

	if _, err := exec.LookPath("iptables"); err != nil {
		res.Errors = append(res.Errors, "iptables binary not found in PATH")
		res.Valid = false
	}

	modules := []string{"xt_hashlimit", "xt_connlimit", "xt_recent", "xt_state"}
	for _, mod := range modules {
		if !moduleLoaded(mod) {
			res.Warns = append(res.Warns, fmt.Sprintf("kernel module %s may not be loaded", mod))
		}
	}

	if rl.MinTTL < 0 || rl.MinTTL > 255 {
		res.Errors = append(res.Errors, "min_ttl must be 0-255"); res.Valid = false
	}
	if rl.MaxTTL < 0 || rl.MaxTTL > 255 {
		res.Errors = append(res.Errors, "max_ttl must be 0-255"); res.Valid = false
	}
	if rl.MinTTL > 0 && rl.MaxTTL > 0 && rl.MinTTL >= rl.MaxTTL {
		res.Errors = append(res.Errors, "min_ttl must be < max_ttl"); res.Valid = false
	}
	if rl.MinPacketSize < 0 || rl.MinPacketSize > 65535 {
		res.Errors = append(res.Errors, "min_packet_size must be 0-65535"); res.Valid = false
	}
	if rl.MaxPacketSize < 0 || rl.MaxPacketSize > 65535 {
		res.Errors = append(res.Errors, "max_packet_size must be 0-65535"); res.Valid = false
	}
	if rl.MinPacketSize > 0 && rl.MaxPacketSize > 0 && rl.MinPacketSize >= rl.MaxPacketSize {
		res.Errors = append(res.Errors, "min_packet_size must be < max_packet_size"); res.Valid = false
	}
	if rl.TCPPSSPerIP < 0 || rl.UDPPSSPerIP < 0 || rl.NewConnsPerSecPerIP < 0 ||
		rl.NewConnsPerSecGlobal < 0 || rl.MaxSimultaneousConnsPerIP < 0 ||
		rl.MaxTotalConns < 0 || rl.TCPSYNRatePerIP < 0 || rl.TCPRSTRatePerIP < 0 {
		res.Errors = append(res.Errors, "rate limit values must be >= 0"); res.Valid = false
	}
	if rl.UDPMaxPayload < 0 || rl.UDPMaxPayload > 65535 {
		res.Errors = append(res.Errors, "udp_max_payload must be 0-65535"); res.Valid = false
	}
	if rl.UDPMinPayload < 0 || rl.UDPMinPayload > 65535 {
		res.Errors = append(res.Errors, "udp_min_payload must be 0-65535"); res.Valid = false
	}
	if rl.UDPMinPayload > 0 && rl.UDPMaxPayload > 0 && rl.UDPMinPayload > rl.UDPMaxPayload {
		res.Errors = append(res.Errors, "udp_min_payload must be <= udp_max_payload"); res.Valid = false
	}
	if protocol == "udp" {
		if rl.TCPPSSPerIP > 0 || rl.TCPSYNRatePerIP > 0 || rl.TCPInvalidStateDrop || rl.TCPRSTRatePerIP > 0 {
			res.Warns = append(res.Warns, "tcp-specific limits set on udp-only proxy — will be ignored")
		}
	}
	return res
}

func moduleLoaded(name string) bool {
	cmd := exec.Command("sh", "-c", "grep -q '^"+name+" ' /proc/modules 2>/dev/null")
	return cmd.Run() == nil
}
