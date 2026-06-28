// Package proxy implements the TCP/UDP reverse-proxy engine, including
// per-port listener lifecycle, upstream load balancing, connection tracking,
// and graceful connection draining for live reload.
//
// Each ProxyInstance is fully isolated: it owns its own context, listener set,
// balancer, health checker and tracker. A panic in one instance is recovered
// and logged — sibling instances are unaffected. See Manager for the
// orchestration layer that spawns/stops/reloads instances.
package proxy

import (
	"errors"
	"fmt"
)

// Resolver maps an origin port to the set of destination ports a connection
// arriving on that origin port may be forwarded to. The semantics differ by
// OneToOne mode:
//
//   one-to-one: origin ports and dest ports are paired positionally. The set of
//   allowed dest ports for a given origin port is exactly the single paired
//   dest port. Spec: "ranges must be equal size".
//
//   fan-out: every dest port is eligible for every origin port; the load
//   balancer picks one of them per connection (or per UDP session).
//
// Build-time validation is performed so the proxy manager may trust that a
// successful NewResolver never returns "no port" at pick time.
type Resolver struct {
	oneToOne bool
	pairs    map[int]int // one-to-one: origin → dest
	fanOut   []int       // fan-out: all dest ports
}

// NewResolver constructs a Resolver. Returns an error when the supplied slices
// are inconsistent with the one-to-one contract (the caller should have already
// validated equivalence of range sizes via config.LoadProxy).
func NewResolver(originPorts, destPorts []int, oneToOne bool) (*Resolver, error) {
	if len(originPorts) == 0 {
		return nil, errors.New("portmap: no origin ports supplied")
	}
	if len(destPorts) == 0 {
		return nil, errors.New("portmap: no dest ports supplied")
	}

	r := &Resolver{oneToOne: oneToOne}

	if oneToOne {
		if len(originPorts) != len(destPorts) {
			return nil, fmt.Errorf(
				"portmap: one-to-one mode requires equal-size port ranges (origin=%d dest=%d)",
				len(originPorts), len(destPorts))
		}
		r.pairs = make(map[int]int, len(originPorts))
		for i, op := range originPorts {
			r.pairs[op] = destPorts[i]
		}
	} else {
		// Fan-out: take a defensive copy of the dest port list.
		r.fanOut = append([]int(nil), destPorts...)
	}
	return r, nil
}

// DestPortsFor returns the dest port set for the supplied origin port. An error
// is returned only for one-to-one mode and only when the supplied origin port is
// not part of the configured range — this never happens in the proxy manager
// because listeners are created exactly from the configured origin port set.
func (r *Resolver) DestPortsFor(originPort int) ([]int, error) {
	if r == nil {
		return nil, errors.New("portmap: resolver is nil")
	}
	if r.oneToOne {
		dp, ok := r.pairs[originPort]
		if !ok {
			return nil, fmt.Errorf("portmap: origin port %d is not part of one-to-one mapping", originPort)
		}
		return []int{dp}, nil
	}
	// Fan-out: origin port is irrelevant to the allowed dest set.
	out := append([]int(nil), r.fanOut...)
	return out, nil
}

// IsOneToOne reports whether the resolver operates in one-to-one mode.
func (r *Resolver) IsOneToOne() bool { return r != nil && r.oneToOne }