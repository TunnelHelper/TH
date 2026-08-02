// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"net/netip"
	"sort"

	"github.com/TunnelHelper/TH/internal/babel/internal/table"
)

// routeKey identifies a route table entry by destination prefix and the
// neighbour it was learnt from (RFC 8966 Section 3.5.3). Local routes use
// an unspecified address as the neighbour key.
type routeKey struct {
	Prefix    netip.Prefix
	Neighbour netip.Addr
}

type RouteTable table.Table[routeKey, *Route]

func NewRouteTable() RouteTable {
	return RouteTable(table.New[routeKey, *Route]())
}

func (t *RouteTable) Lookup(pfx netip.Prefix, neighbour netip.Addr) (*Route, bool) {
	return (*table.Table[routeKey, *Route])(t).Lookup(routeKey{
		Prefix:    pfx,
		Neighbour: neighbour,
	})
}

func (t *RouteTable) LookupByNeighbour(pfx netip.Prefix, n *Neighbour) (*Route, bool) {
	if n == nil {
		return (*table.Table[routeKey, *Route])(t).Lookup(routeKey{
			Prefix:    pfx,
			Neighbour: netip.Addr{},
		})
	}
	return (*table.Table[routeKey, *Route])(t).Lookup(routeKey{
		Prefix:    pfx,
		Neighbour: n.Address,
	})
}

func (t *RouteTable) Insert(r *Route) {
	pfx, neighbour := r.key()
	(*table.Table[routeKey, *Route])(t).Insert(routeKey{
		Prefix:    pfx,
		Neighbour: neighbour,
	}, r)
}

func (t *RouteTable) Remove(r *Route) {
	pfx, neighbour := r.key()
	(*table.Table[routeKey, *Route])(t).Remove(routeKey{
		Prefix:    pfx,
		Neighbour: neighbour,
	})
}

// All returns a snapshot of all routes.
func (t *RouteTable) All() []*Route {
	routes := make([]*Route, 0)
	_ = (*table.Table[routeKey, *Route])(t).ForEach(func(_ routeKey, r *Route) error {
		routes = append(routes, r)
		return nil
	})
	return routes
}

// ForPrefix returns a snapshot of all routes for a destination prefix.
func (t *RouteTable) ForPrefix(pfx netip.Prefix) []*Route {
	routes := make([]*Route, 0)
	_ = (*table.Table[routeKey, *Route])(t).ForEach(func(key routeKey, r *Route) error {
		if key.Prefix == pfx {
			routes = append(routes, r)
		}
		return nil
	})
	return routes
}

// Prefixes returns the distinct destination prefixes in the table.
func (t *RouteTable) Prefixes() []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	prefixes := make([]netip.Prefix, 0)
	_ = (*table.Table[routeKey, *Route])(t).ForEach(func(key routeKey, _ *Route) error {
		if _, ok := seen[key.Prefix]; ok {
			return nil
		}
		seen[key.Prefix] = struct{}{}
		prefixes = append(prefixes, key.Prefix)
		return nil
	})
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Compare(prefixes[j].Addr()) < 0
	})
	return prefixes
}

// RemoveNeighbour drops every route learnt from the given neighbour.
func (t *RouteTable) RemoveNeighbour(n *Neighbour) {
	toRemove := make([]*Route, 0)
	_ = (*table.Table[routeKey, *Route])(t).ForEach(func(_ routeKey, r *Route) error {
		if r.Neighbour == n {
			toRemove = append(toRemove, r)
		}
		return nil
	})
	for _, r := range toRemove {
		t.Remove(r)
	}
}
