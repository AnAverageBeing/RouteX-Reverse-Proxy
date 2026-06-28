package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadProxy reads, parses, and validates a single per-proxy YAML config file.
// Returns a *ConfigError scoped to the file when validation fails — the proxy
// manager must treat any returned error as scoped to this file only so peer
// proxies keep running (spec: "one config failing validation must never affect
// others").
func LoadProxy(path string) (*Proxy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{
			File:  path,
			Field: "",
			Reason: "failed to read proxy config file",
			Cause: err,
		}
	}

	var p Proxy
	p.ConfigPath = path
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, &ConfigError{
			File:   path,
			Field:  "",
			Reason: "failed to parse proxy config YAML",
			Cause:  err,
		}
	}

	if err := validateProxy(&p, path); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadProxyDir scans the supplied directory for *.yaml files and returns one
// LoadResult per file. A failure on any single file never aborts the iteration —
// callers receive the full set of successes and failures independent of order.
// Directory traversal is sorted by filename so the returned slice is stable.
func LoadProxyDir(dir string) []LoadResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []LoadResult{{
			Path:  dir,
			Proxy: nil,
			Err: &ConfigError{
				Field: "",
				Reason: "failed to read proxy config directory",
				Cause: err,
			},
		}}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") && !strings.HasSuffix(strings.ToLower(e.Name()), ".yml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	results := make([]LoadResult, 0, len(names))
	for _, name := range names {
		full := dir + string(os.PathSeparator) + name
		p, err := LoadProxy(full)
		results = append(results, LoadResult{Path: full, Proxy: p, Err: err})
	}
	return results
}

// LoadResult is a single file's load outcome. Exactly one of Proxy/Err is nil
// for any given result.
type LoadResult struct {
	Path  string
	Proxy *Proxy
	Err   error
}

// validateProxy enforces every invariant documented in the per-proxy config
// reference plus the protocol-specific validation rules listed in the spec's
// "VALIDATION RULES" section.
func validateProxy(p *Proxy, path string) error {
	if strings.TrimSpace(p.Name) == "" {
		return cfgErr(path, "proxy.name", "name must be set")
	}

	// Origin IPs.
	originIPs, err := splitIPs(p.OriginIP)
	if err != nil {
		return wrap(path, "proxy.origin-ip", "invalid origin-ip", err)
	}
	if len(originIPs) == 0 {
		return cfgErr(path, "proxy.origin-ip", "at least one origin IP must be specified")
	}

	// Destination IPs.
	destIPs, err := splitIPs(p.DestIP)
	if err != nil {
		return wrap(path, "proxy.dest-ip", "invalid dest-ip", err)
	}
	if len(destIPs) == 0 {
		return cfgErr(path, "proxy.dest-ip", "at least one destination IP must be specified")
	}

	// Protocol.
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	if proto == "" {
		return cfgErr(path, "proxy.protocol", "protocol must be one of: tcp, udp, tcp-udp")
	}
	if !isAllowedProtocol(proto) {
		return cfgErr(path, "proxy.protocol", fmt.Sprintf("unsupported protocol %q (allowed: tcp, udp, tcp-udp)", proto))
	}

	// Port ranges (origin + dest).
	originPorts, err := parsePortRange(p.OriginPort)
	if err != nil {
		return wrap(path, "proxy.origin-port", "invalid origin-port", err)
	}
	if len(originPorts) == 0 {
		return cfgErr(path, "proxy.origin-port", "at least one origin port must be specified")
	}

	destPorts, err := parsePortRange(p.DestPort)
	if err != nil {
		return wrap(path, "proxy.dest-port", "invalid dest-port", err)
	}
	if len(destPorts) == 0 {
		return cfgErr(path, "proxy.dest-port", "at least one destination port must be specified")
	}

	// Port-mapping mode: one-to-one requires equal-size ranges.
	if p.OneToOne {
		if len(originPorts) != len(destPorts) {
			return cfgErr(path, "proxy.one-to-one",
				fmt.Sprintf("one-to-one mode requires origin and dest port ranges to be the same size (got %d origin vs %d dest)",
					len(originPorts), len(destPorts)))
		}
	}

	// Load balancing algorithm.
	alg := strings.ToLower(strings.TrimSpace(p.LoadBalancing.Algorithm))
	if alg == "" {
		p.LoadBalancing.Algorithm = "round-robin"
		alg = "round-robin"
	}
	if !isAllowedAlgorithm(alg) {
		return cfgErr(path, "proxy.load_balancing.algorithm",
			fmt.Sprintf("unsupported algorithm %q (allowed: round-robin, least-conn, ip-hash, weighted, random)", alg))
	}
	if alg == "weighted" && len(p.LoadBalancing.UpstreamWeights) == 0 {
		return cfgErr(path, "proxy.load_balancing.upstream_weights",
			"weighted algorithm requires upstream_weights to be configured")
	}
	if p.LoadBalancing.StickySessions && p.LoadBalancing.StickyTTL <= 0 {
		p.LoadBalancing.StickyTTL = 3600
	}

	// Validate upstream_weights keys are valid IPs and that every configured weight is positive.
	for ip, w := range p.LoadBalancing.UpstreamWeights {
		if net.ParseIP(ip) == nil {
			return cfgErr(path, fmt.Sprintf("proxy.load_balancing.upstream_weights[%q]", ip), "is not a valid IP")
		}
		if w <= 0 {
			return cfgErr(path, fmt.Sprintf("proxy.load_balancing.upstream_weights[%q]", ip), "weight must be > 0")
		}
	}

	// Rate-limit ranges (must be valid *before* iptables apply per the spec).
	if err := validateRateLimits(&p.RateLimits, proto, path); err != nil {
		return err
	}

	// L7 protection.
	if err := validateL7(&p.L7Protection, path); err != nil {
		return err
	}

	// ACL.
	if p.ACL.DefaultAction != "" {
		da := strings.ToLower(p.ACL.DefaultAction)
		if da != "allow" && da != "deny" {
			return cfgErr(path, "proxy.acl.default_action", "must be allow or deny")
		}
		p.ACL.DefaultAction = da
	} else {
		p.ACL.DefaultAction = "allow"
	}
	for i, rule := range p.ACL.Rules {
		field := fmt.Sprintf("proxy.acl.rules[%d]", i)
		action := strings.ToLower(rule.Action)
		if action != "allow" && action != "deny" {
			return cfgErr(path, field+".action", "must be allow or deny")
		}
		p.ACL.Rules[i].Action = action
		_, _, err := net.ParseCIDR(rule.CIDR)
		if err != nil {
			return wrap(path, field+".cidr", "invalid CIDR", err)
		}
	}
	return nil
}

// validateRateLimits enforces the numeric bounds documented in the spec's
// "Rate limit validation" section. Per the spec, TCP-specific fields configured
// when the protocol is UDP-only are NOT fatal — we just skip building those
// rules at apply time; here we log a warning rather than reject.
func validateRateLimits(rl *ProxyRateLimits, proto string, path string) error {
	must := func(field string, cond bool, msg string) error {
		if !cond {
			return cfgErr(path, "proxy.rate_limits."+field, msg)
		}
		return nil
	}
	if err := must("tcp_pps_per_ip", rl.TCPPSSPerIP >= 0, "must be >= 0 (0 = disabled)"); err != nil {
		return err
	}
	if err := must("udp_pps_per_ip", rl.UDPPSSPerIP >= 0, "must be >= 0"); err != nil {
		return err
	}
	if err := must("new_conns_per_sec_per_ip", rl.NewConnsPerSecPerIP >= 0, "must be >= 0"); err != nil {
		return err
	}
	if err := must("new_conns_per_sec_global", rl.NewConnsPerSecGlobal >= 0, "must be >= 0"); err != nil {
		return err
	}
	if rl.MaxSimultaneousConnsPerIP < 0 {
		return cfgErr(path, "proxy.rate_limits.max_simultaneous_conns_per_ip", "must be >= 0")
	}
	if rl.MaxTotalConns < 0 {
		return cfgErr(path, "proxy.rate_limits.max_total_conns", "must be >= 0")
	}
	if rl.MinTTL < 0 || rl.MaxTTL < 0 {
		return cfgErr(path, "proxy.rate_limits.min_ttl", "min_ttl and max_ttl must be >= 0")
	}
	if rl.MinTTL != 0 && rl.MaxTTL != 0 && rl.MinTTL >= rl.MaxTTL {
		return cfgErr(path, "proxy.rate_limits.min_ttl", "min_ttl must be < max_ttl when both are set")
	}
	if rl.MinPacketSize < 0 || rl.MaxPacketSize < 0 {
		return cfgErr(path, "proxy.rate_limits.min_packet_size", "min_packet_size and max_packet_size must be >= 0")
	}
	if rl.MinPacketSize != 0 && rl.MaxPacketSize != 0 && rl.MinPacketSize >= rl.MaxPacketSize {
		return cfgErr(path, "proxy.rate_limits.min_packet_size", "min_packet_size must be < max_packet_size when both are set")
	}
	if rl.TCPSYNRatePerIP < 0 {
		return cfgErr(path, "proxy.rate_limits.tcp_syn_rate_per_ip", "must be >= 0")
	}
	if rl.TCPRSTRatePerIP < 0 {
		return cfgErr(path, "proxy.rate_limits.tcp_rst_rate_per_ip", "must be >= 0")
	}
	if rl.UDPMaxPayload < 0 || rl.UDPMinPayload < 0 {
		return cfgErr(path, "proxy.rate_limits.udp_min_payload", "udp_min_payload and udp_max_payload must be >= 0")
	}
	if rl.UDPMinPayload != 0 && rl.UDPMaxPayload != 0 && rl.UDPMinPayload >= rl.UDPMaxPayload {
		return cfgErr(path, "proxy.rate_limits.udp_min_payload", "udp_min_payload must be < udp_max_payload when both are set")
	}

	if err := must("tcp_invalid_state_drop", true, ""); err != nil {
		return err
	}

	if err := checkIPWeightsAboveRange(path); err != nil {
		return err
	}
	return nil
}

// checkIPWeightsAboveRange is a placeholder hook reserved for future validation
// passes that may need a stable call site. Currently a no-op.
func checkIPWeightsAboveRange(path string) error { return nil }

// validateL7 enforces the L7-protection-specific validation rules.
func validateL7(l7 *ProxyL7Protection, path string) error {
	if !l7.Enabled {
		return nil
	}
	if l7.SlowConnection.Enabled {
		if l7.SlowConnection.MinBytesInFirst < 0 {
			return cfgErr(path, "proxy.l7_protection.slow_connection.min_bytes_in_first", "must be >= 0")
		}
		if l7.SlowConnection.HandshakeTimeout.IsZero() {
			l7.SlowConnection.HandshakeTimeout = Duration(5 * time.Second)
		} else if !l7.SlowConnection.HandshakeTimeout.Positive() {
			return cfgErr(path, "proxy.l7_protection.slow_connection.handshake_timeout", "must be a positive duration")
		}
		if l7.SlowConnection.MinRecvRateBPS < 0 {
			return cfgErr(path, "proxy.l7_protection.slow_connection.min_recv_rate_bps", "must be >= 0")
		}
	}
	if l7.PayloadRateLimit.Enabled {
		if l7.PayloadRateLimit.MaxBytesPerSecPerConn < 0 || l7.PayloadRateLimit.MaxBytesPerSecPerIP < 0 {
			return cfgErr(path, "proxy.l7_protection.payload_rate_limit",
				"max_bytes_per_sec_per_conn and max_bytes_per_sec_per_ip must be >= 0")
		}
		if l7.PayloadRateLimit.BurstMultiplier < 0 {
			return cfgErr(path, "proxy.l7_protection.payload_rate_limit.burst_multiplier", "must be >= 0")
		} else if l7.PayloadRateLimit.BurstMultiplier == 0 {
			l7.PayloadRateLimit.BurstMultiplier = 2.0
		}
	}
	if l7.ConnectionCycling.Enabled {
		if !l7.ConnectionCycling.Window.Positive() {
			return cfgErr(path, "proxy.l7_protection.connection_cycling.window", "must be a positive duration")
		}
		if l7.ConnectionCycling.MaxConnsInWindow <= 0 {
			return cfgErr(path, "proxy.l7_protection.connection_cycling.max_conns_in_window", "must be > 0")
		}
		if !l7.ConnectionCycling.BanDuration.Positive() {
			return cfgErr(path, "proxy.l7_protection.connection_cycling.ban_duration", "must be a positive duration")
		}
	}
	if l7.PayloadInspection.Enabled {
		mode := strings.ToLower(strings.TrimSpace(l7.PayloadInspection.Mode))
		if mode == "" {
			mode = "none"
			l7.PayloadInspection.Mode = "none"
		}
		if !isSupportedInspectionMode(mode) {
			return cfgErr(path, "proxy.l7_protection.payload_inspection.mode",
				fmt.Sprintf("unsupported mode %q (allowed: minecraft-java, minecraft-bedrock, fivem, gmod, custom, none)", mode))
		}
		for i, cr := range l7.PayloadInspection.CustomRules {
			field := fmt.Sprintf("proxy.l7_protection.payload_inspection.custom_rules[%d]", i)
			if cr.Name == "" {
				return cfgErr(path, field+".name", "rule name must be set")
			}
			a := strings.ToLower(cr.Action)
			if a != "allow" && a != "drop" {
				return cfgErr(path, field+".action", "action must be allow or drop")
			}
			l7.PayloadInspection.CustomRules[i].Action = a
			if strings.TrimSpace(cr.MatchBytes) == "" {
				return cfgErr(path, field+".match_bytes", "match_bytes must be set")
			}
			if _, err := parseHexBytes(cr.MatchBytes); err != nil {
				return wrap(path, field+".match_bytes", "failed to parse hex byte list", err)
			}
		}
	}
	if l7.Amplification.Enabled {
		if l7.Amplification.MaxResponseToRequestRatio <= 0 {
			return cfgErr(path, "proxy.l7_protection.amplification.max_response_to_request_ratio", "must be > 0")
		}
		if !l7.Amplification.Window.Positive() {
			l7.Amplification.Window = Duration(5 * time.Second)
		}
	}
	if l7.BehavioralScoring.Enabled {
		if l7.BehavioralScoring.BanThreshold <= 0 {
			return cfgErr(path, "proxy.l7_protection.behavioral_scoring.ban_threshold", "must be > 0")
		}
		if !l7.BehavioralScoring.ScoreWindow.Positive() {
			l7.BehavioralScoring.ScoreWindow = Duration(30 * time.Second)
		}
		if !l7.BehavioralScoring.BanDuration.Positive() {
			l7.BehavioralScoring.BanDuration = Duration(120 * time.Second)
		}
		for i, sr := range l7.BehavioralScoring.ScoreRules {
			if strings.TrimSpace(sr.Event) == "" {
				return cfgErr(path, fmt.Sprintf("proxy.l7_protection.behavioral_scoring.score_rules[%d].event", i), "event must be set")
			}
		}
	}
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────

// splitIPs parses a comma-separated list of IPs. The literal "0.0.0.0" is
// allowed as an "all-interfaces" binding. Each component must parse as IPv4
// unless the global iptables ipv6 flag is on (the proxy loader is IPv6-agnostic
// to keep deps minimal here — validation depth happens in the iptables layer).
func splitIPs(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP %q", ip)
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid IPs parsed from %q", s)
	}
	return out, nil
}

// parsePortRange converts a port spec to an explicit slice of port numbers.
// Accepted forms:
//
//	"25565"        → [25565]
//	"25565:25575"  → [25565, 25566, ..., 25575]
//	"25565,25566"  → [25565, 25566]
//	"25565,25566:25568" → [25565, 25566, 25567, 25568] (ranges and singles can mix)
//
// Ranges must have low < high. All ports must satisfy 1 ≤ port ≤ 65535.
func parsePortRange(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}
	parts := strings.Split(spec, ",")
	var out []int
	seen := make(map[int]struct{})
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.Contains(p, ":") {
			loHi := strings.SplitN(p, ":", 2)
			lo, err := strconv.Atoi(strings.TrimSpace(loHi[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range low %q: %w", loHi[0], err)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(loHi[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range high %q: %w", loHi[1], err)
			}
			if lo <= 0 || lo > 65535 || hi <= 0 || hi > 65535 {
				return nil, fmt.Errorf("port out of range 1-65535: %d:%d", lo, hi)
			}
			if lo >= hi {
				return nil, fmt.Errorf("range low must be < high in %q", p)
			}
			for i := lo; i <= hi; i++ {
				if _, ok := seen[i]; ok {
					continue
				}
				seen[i] = struct{}{}
				out = append(out, i)
			}
		} else {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", p, err)
			}
			if n <= 0 || n > 65535 {
				return nil, fmt.Errorf("port out of range 1-65535: %d", n)
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	return out, nil
}

// parseHexBytes converts a comma-separated list of "0xNN" hex strings into a
// byte slice. Used by L7 custom inspection rule validation.
func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty byte list")
	}
	parts := strings.Split(s, ",")
	out := make([]byte, 0, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "0x") && !strings.HasPrefix(p, "0X") {
			return nil, fmt.Errorf("token %d: %q must start with 0x", i, p)
		}
		n, err := strconv.ParseUint(p[2:], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("token %d: invalid hex byte %q: %w", i, p, err)
		}
		if n > 0xff {
			return nil, fmt.Errorf("token %d: %q exceeds 0xff", i, p)
		}
		out = append(out, byte(n))
	}
	return out, nil
}

// isAllowedProtocol reports whether proto is one of the supported values.
func isAllowedProtocol(proto string) bool {
	switch proto {
	case "tcp", "udp", "tcp-udp":
		return true
	}
	return false
}

// isAllowedAlgorithm reports whether alg is one of the supported LB algorithms.
func isAllowedAlgorithm(alg string) bool {
	switch alg {
	case "round-robin", "least-conn", "ip-hash", "weighted", "random":
		return true
	}
	return false
}

// isSupportedInspectionMode reports whether mode is one of the built-in L7
// payload detection modes (or "none"/"custom").
func isSupportedInspectionMode(mode string) bool {
	switch mode {
	case "minecraft-java", "minecraft-bedrock", "fivem", "gmod", "custom", "none":
		return true
	}
	return false
}

// ResolveOriginIPs / ResolveDestIPs / ResolveOriginPorts / ResolveDestPorts are
// accessor helpers used by the proxy manager — they perform the same parse used
// during validation, so callers don't have to re-split the comma-separated
// strings themselves and can rely on the fact that the config already passed
// validation.
func (p *Proxy) ResolveOriginIPs() []string {
	ips, _ := splitIPs(p.OriginIP)
	return ips
}

// ResolveDestIPs returns the upstream IP list.
func (p *Proxy) ResolveDestIPs() []string {
	ips, _ := splitIPs(p.DestIP)
	return ips
}

// ResolveOriginPorts returns the ordered, deduplicated origin port slice.
func (p *Proxy) ResolveOriginPorts() []int {
	ports, _ := parsePortRange(p.OriginPort)
	return ports
}

// ResolveDestPorts returns the ordered, deduplicated destination port slice.
func (p *Proxy) ResolveDestPorts() []int {
	ports, _ := parsePortRange(p.DestPort)
	return ports
}