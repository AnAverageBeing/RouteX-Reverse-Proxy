package iptables

import (
	"fmt"
	"strings"
	"sync"

	ipt "github.com/coreos/go-iptables/iptables"
	"go.uber.org/zap"
)

type Manager struct {
	ipt4          *ipt.IPTables
	ipt6          *ipt.IPTables
	logger        *zap.Logger
	ipv6          bool
	commentPrefix string

	mu          sync.Mutex
	activeRules map[string][]Rule
}

func NewManager(commentPrefix string, ipv6 bool, logger *zap.Logger) (*Manager, error) {
	ipt4, err := ipt.New()
	if err != nil {
		return nil, fmt.Errorf("iptables init: %w", err)
	}
	var ipt6 *ipt.IPTables
	if ipv6 {
		ipt6, err = ipt.NewWithProtocol(ipt.ProtocolIPv6)
		if err != nil {
			logger.Warn("ip6tables init failed, ipv6 management disabled", zap.Error(err))
			ipt6 = nil
		}
	}
	return &Manager{
		ipt4:          ipt4,
		ipt6:          ipt6,
		logger:        logger,
		ipv6:          ipv6 && ipt6 != nil,
		commentPrefix: commentPrefix,
		activeRules:   make(map[string][]Rule),
	}, nil
}

func (m *Manager) ApplyRules(proxyName string, ports []int, rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.deleteProxyRules(proxyName); err != nil {
		m.logger.Warn("failed to delete old iptables rules",
			zap.String("proxy", proxyName), zap.Error(err))
	}

	for _, rule := range rules {
		if err := m.ipt4.Append(rule.Table, rule.Chain, rule.Spec...); err != nil {
			return fmt.Errorf("iptables append failed: %w", err)
		}
		if m.ipv6 && m.ipt6 != nil {
			_ = m.ipt6.Append(rule.Table, rule.Chain, rule.Spec...)
		}
	}

	m.activeRules[proxyName] = rules
	m.logger.Info("iptables rules applied",
		zap.String("proxy", proxyName), zap.Int("rules", len(rules)))
	return nil
}

func (m *Manager) FlushProxy(proxyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteProxyRules(proxyName)
}

func (m *Manager) OrphanSweep(activePorts map[string][]int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	chains := []string{"INPUT", "FORWARD"}
	for _, chain := range chains {
		rules, err := m.ipt4.List("filter", chain)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if !strings.Contains(rule, m.commentPrefix) {
				continue
			}
			comment := extractComment(rule)
			if comment == "" {
				continue
			}
			owned := false
			for _, ports := range activePorts {
				portComment := portList(ports)
				if strings.HasSuffix(comment, portComment) {
					owned = true
					break
				}
			}
			if !owned {
				m.logger.Info("removing orphan iptables rule",
					zap.String("chain", chain), zap.String("comment", comment))
				_ = m.deleteRuleByComment("filter", chain, comment)
			}
		}
	}
	return nil
}

func (m *Manager) ActiveRuleCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, rules := range m.activeRules {
		count += len(rules)
	}
	return count
}

func (m *Manager) ListRules() map[string][]Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]Rule, len(m.activeRules))
	for k, v := range m.activeRules {
		out[k] = append([]Rule(nil), v...)
	}
	return out
}

func (m *Manager) deleteProxyRules(proxyName string) error {
	rules, ok := m.activeRules[proxyName]
	if !ok {
		return m.deleteByPrefix(proxyName)
	}
	for _, rule := range rules {
		if err := m.ipt4.Delete(rule.Table, rule.Chain, rule.Spec...); err != nil {
			m.logger.Debug("iptables delete (rule may already be gone)",
				zap.String("proxy", proxyName), zap.Error(err))
		}
	}
	delete(m.activeRules, proxyName)
	return nil
}

func (m *Manager) deleteByPrefix(proxyName string) error {
	chains := []string{"INPUT", "FORWARD"}
	for _, chain := range chains {
		rules, err := m.ipt4.List("filter", chain)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if strings.Contains(rule, m.commentPrefix) {
				comment := extractComment(rule)
				if comment != "" {
					_ = m.deleteRuleByComment("filter", chain, comment)
				}
			}
		}
	}
	return nil
}

func (m *Manager) deleteRuleByComment(table, chain, comment string) error {
	rules, err := m.ipt4.List(table, chain)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if strings.Contains(rule, comment) {
			specs := parseRuleSpec(rule)
			if len(specs) > 0 {
				return m.ipt4.Delete(table, chain, specs...)
			}
		}
	}
	return nil
}

func extractComment(rule string) string {
	start := strings.Index(rule, "/* ")
	if start == -1 {
		return ""
	}
	start += 3
	end := strings.Index(rule[start:], " */")
	if end == -1 {
		return rule[start:]
	}
	return rule[start : start+end]
}

func parseRuleSpec(rule string) []string {
	var specs []string
	if strings.Contains(rule, "tcp") {
		specs = append(specs, "-p", "tcp")
	} else if strings.Contains(rule, "udp") {
		specs = append(specs, "-p", "udp")
	}
	if idx := strings.Index(rule, "dpt:"); idx != -1 {
		port := rule[idx+4:]
		if space := strings.IndexAny(port, " \t"); space != -1 {
			port = port[:space]
		}
		specs = append(specs, "--dport", port)
	}
	comment := extractComment(rule)
	if comment != "" {
		specs = append(specs, "-m", "comment", "--comment", comment)
	}
	return specs
}
