package iptables

import (
	"fmt"
	"strings"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
)

type Rule struct {
	Table   string
	Chain   string
	Spec    []string
	Comment string
}

func BuildRules(proxyName string, ports []int, rl config.ProxyRateLimits, protocol string, commentPrefix string) []Rule {
	var rules []Rule
	portStr := portList(ports)

	if rl.TCPPSSPerIP > 0 && (protocol == "tcp" || protocol == "tcp-udp") {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "TCP-PPS", ports),
			Spec: []string{
				"-p", "tcp", "--dport", portStr,
				"-m", "hashlimit",
				"--hashlimit-name", fmt.Sprintf("routex_tcp_pps_%s", proxyName),
				"--hashlimit-above", fmt.Sprintf("%d/sec", rl.TCPPSSPerIP),
				"--hashlimit-mode", "srcip",
				"-m", "comment", "--comment", comment(commentPrefix, "TCP-PPS", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.UDPPSSPerIP > 0 && (protocol == "udp" || protocol == "tcp-udp") {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "UDP-PPS", ports),
			Spec: []string{
				"-p", "udp", "--dport", portStr,
				"-m", "hashlimit",
				"--hashlimit-name", fmt.Sprintf("routex_udp_pps_%s", proxyName),
				"--hashlimit-above", fmt.Sprintf("%d/sec", rl.UDPPSSPerIP),
				"--hashlimit-mode", "srcip",
				"-m", "comment", "--comment", comment(commentPrefix, "UDP-PPS", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.NewConnsPerSecPerIP > 0 {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "NewConn-PerIP", ports),
			Spec: []string{
				"-p", "tcp", "--dport", portStr, "--syn",
				"-m", "recent",
				"--name", fmt.Sprintf("routex_newconn_%s", proxyName),
				"--rcheck", "--seconds", "1",
				"--hitcount", fmt.Sprintf("%d", rl.NewConnsPerSecPerIP+1),
				"-m", "comment", "--comment", comment(commentPrefix, "NewConn-PerIP", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.MaxSimultaneousConnsPerIP > 0 {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "MaxSimul-PerIP", ports),
			Spec: []string{
				"-p", "tcp", "--dport", portStr,
				"-m", "connlimit",
				"--connlimit-above", fmt.Sprintf("%d", rl.MaxSimultaneousConnsPerIP),
				"--connlimit-mask", "32",
				"-m", "comment", "--comment", comment(commentPrefix, "MaxSimul-PerIP", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.MaxTotalConns > 0 {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "MaxTotal", ports),
			Spec: []string{
				"-p", "tcp", "--dport", portStr,
				"-m", "connlimit",
				"--connlimit-above", fmt.Sprintf("%d", rl.MaxTotalConns),
				"-m", "comment", "--comment", comment(commentPrefix, "MaxTotal", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.DropFragmentedPackets {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "FragDrop", ports),
			Spec: []string{
				"-p", protoForProtocol(protocol), "--dport", portStr, "-f",
				"-m", "comment", "--comment", comment(commentPrefix, "FragDrop", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.TCPSYNRatePerIP > 0 && (protocol == "tcp" || protocol == "tcp-udp") {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "SYN-Rate", ports),
			Spec: []string{
				"-p", "tcp", "--dport", portStr, "--syn",
				"-m", "hashlimit",
				"--hashlimit-name", fmt.Sprintf("routex_syn_%s", proxyName),
				"--hashlimit-above", fmt.Sprintf("%d/sec", rl.TCPSYNRatePerIP),
				"--hashlimit-mode", "srcip",
				"-m", "comment", "--comment", comment(commentPrefix, "SYN-Rate", ports),
				"-j", "DROP",
			},
		})
	}

	if rl.TCPInvalidStateDrop && (protocol == "tcp" || protocol == "tcp-udp") {
		rules = append(rules, Rule{
			Table: "filter", Chain: "INPUT",
			Comment: comment(commentPrefix, "Invalid-State", ports),
			Spec: []string{
				"-p", "tcp", "--dport", portStr,
				"-m", "state", "--state", "INVALID",
				"-m", "comment", "--comment", comment(commentPrefix, "Invalid-State", ports),
				"-j", "DROP",
			},
		})
	}

	return rules
}

func portList(ports []int) string {
	if len(ports) == 1 {
		return fmt.Sprintf("%d", ports[0])
	}
	if len(ports) > 1 {
		contiguous := true
		for i := 1; i < len(ports); i++ {
			if ports[i] != ports[i-1]+1 {
				contiguous = false
				break
			}
		}
		if contiguous {
			return fmt.Sprintf("%d:%d", ports[0], ports[len(ports)-1])
		}
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

func comment(prefix, ruleType string, ports []int) string {
	return fmt.Sprintf("%s-%s-%s", prefix, ruleType, portList(ports))
}

func protoForProtocol(protocol string) string {
	switch protocol {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "tcp-udp":
		return "tcp"
	}
	return "tcp"
}
