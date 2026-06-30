// Package acl provides IP-based access control with whitelist/blacklist semantics.
//
// An Engine evaluates a source IP against an ordered list of CIDR rules. The
// first matching rule wins. If no rule matches, a configurable default action
// (allow or deny) is applied.
//
// Rules can be added and removed at runtime without restarting the proxy,
// enabling live management via the REST API.
package acl

import (
	"net"
	"sync"
	"sync/atomic"
)

// Action represents the result of an ACL check.
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Rule is a single CIDR-scoped allow or deny decision.
type Rule struct {
	Action  Action `json:"action" yaml:"action"`
	CIDR    string `json:"cidr" yaml:"cidr"`
	Comment string `json:"comment" yaml:"comment"`

	cidrNet *net.IPNet `json:"-" yaml:"-"`
}

// Engine evaluates source IPs against an ordered rule set.
type Engine struct {
	mu            sync.RWMutex
	defaultAction Action
	rules         []Rule
	name          string
	enabled       bool

	allowed uint64
	denied  uint64
}

// NewEngine creates an ACL engine with the given default action and rules.
func NewEngine(name string, defaultAction Action, rules []Rule, enabled bool) (*Engine, error) {
	e := &Engine{
		name:          name,
		defaultAction: defaultAction,
		enabled:       enabled,
	}
	compiled := make([]Rule, 0, len(rules))
	for _, r := range rules {
		cr := Rule{Action: r.Action, CIDR: r.CIDR, Comment: r.Comment}
		if _, n, err := net.ParseCIDR(r.CIDR); err == nil {
			cr.cidrNet = n
		} else if ip := net.ParseIP(r.CIDR); ip != nil {
			if ip.To4() != nil {
				cr.cidrNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				cr.cidrNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		} else {
			return nil, &net.ParseError{Type: "CIDR/IP", Text: r.CIDR}
		}
		compiled = append(compiled, cr)
	}
	e.rules = compiled
	return e, nil
}

// Check evaluates the source IP against all rules in order.
func (e *Engine) Check(ip net.IP) string {
	// Defensive: a nil engine (e.g. a typed-nil *Engine stored in an ACLChecker
	// interface) must never panic — treat it as "no ACL configured" = allow.
	if e == nil || !e.enabled || ip == nil {
		return string(Allow)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if rule.cidrNet != nil && rule.cidrNet.Contains(ip) {
			if rule.Action == Allow {
				atomic.AddUint64(&e.allowed, 1)
			} else {
				atomic.AddUint64(&e.denied, 1)
			}
			return string(rule.Action)
		}
	}
	if e.defaultAction == Allow {
		atomic.AddUint64(&e.allowed, 1)
	} else {
		atomic.AddUint64(&e.denied, 1)
	}
	return string(e.defaultAction)
}

// AddRule appends a new rule at runtime.
func (e *Engine) AddRule(action Action, cidr, comment string) error {
	r := Rule{Action: action, CIDR: cidr, Comment: comment}
	if _, n, err := net.ParseCIDR(cidr); err == nil {
		r.cidrNet = n
	} else if ip := net.ParseIP(cidr); ip != nil {
		if ip.To4() != nil {
			r.cidrNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			r.cidrNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	} else {
		return &net.ParseError{Type: "CIDR/IP", Text: cidr}
	}
	e.mu.Lock()
	e.rules = append(e.rules, r)
	e.mu.Unlock()
	return nil
}

// RemoveRule removes rules whose CIDR matches. Returns count removed.
func (e *Engine) RemoveRule(cidr string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	filtered := make([]Rule, 0, len(e.rules))
	removed := 0
	for _, r := range e.rules {
		if r.CIDR == cidr {
			removed++
		} else {
			filtered = append(filtered, r)
		}
	}
	e.rules = filtered
	return removed
}

// SetDefaultAction changes the default action at runtime.
func (e *Engine) SetDefaultAction(action Action) {
	e.mu.Lock()
	e.defaultAction = action
	e.mu.Unlock()
}

// Rules returns a snapshot of all rules.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	for i := range out {
		out[i].cidrNet = nil
	}
	return out
}

// DefaultAction returns the current default action.
func (e *Engine) DefaultAction() Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.defaultAction
}

// Stats returns allow/deny counters.
func (e *Engine) Stats() (allowed, denied uint64) {
	return atomic.LoadUint64(&e.allowed), atomic.LoadUint64(&e.denied)
}

// Name returns the engine name.
func (e *Engine) Name() string { return e.name }

// IsEnabled reports whether the ACL engine is active.
func (e *Engine) IsEnabled() bool { return e.enabled }

// SetEnabled enables or disables at runtime.
func (e *Engine) SetEnabled(enabled bool) {
	e.mu.Lock()
	e.enabled = enabled
	e.mu.Unlock()
}

// ReplaceRules atomically replaces all rules.
func (e *Engine) ReplaceRules(rules []Rule) {
	compiled := make([]Rule, 0, len(rules))
	for _, r := range rules {
		cr := Rule{Action: r.Action, CIDR: r.CIDR, Comment: r.Comment}
		if _, n, err := net.ParseCIDR(r.CIDR); err == nil {
			cr.cidrNet = n
		} else if ip := net.ParseIP(r.CIDR); ip != nil {
			if ip.To4() != nil {
				cr.cidrNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				cr.cidrNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		compiled = append(compiled, cr)
	}
	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()
}
