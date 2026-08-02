package model

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
)

const mainRouteTable = 254

const (
	MainRulePriority        = 32766
	SRv6RulePriorityMin     = 1
	SRv6RulePriorityMax     = MainRulePriority - 1
	SRv6AutoRulePriorityMin = 20000
	SRv6AutoRulePriorityMax = 29999
)

const (
	managedRouteRealmPrefix = 0x40000000
	managedRouteRealmMask   = 0x3fffffff
)

type RouteClaim struct {
	Table  int
	Prefix netip.Prefix
}

// ManagedRouteRealm returns a stable record-level route ownership tag. The
// high bits reserve a TH-specific realm range while keeping the value safe on
// 32-bit platforms.
func ManagedRouteRealm(t Tunnel) int {
	digest := sha256.Sum256([]byte(t.ID))
	return managedRouteRealmPrefix | int(binary.BigEndian.Uint32(digest[8:12])&managedRouteRealmMask)
}

func IsManagedRouteRealm(realm int) bool {
	return realm&^managedRouteRealmMask == managedRouteRealmPrefix
}

// ManagedRulePriorities reserves stable, non-overlapping priority ranges for
// policy rules whose kernel API has no user-defined ownership tag.
func ManagedRulePriorities(t Tunnel) []int {
	digest := sha256.Sum256([]byte(t.ID))
	switch t.Kind {
	case KindWireGuard:
		base := 100000 + int(binary.BigEndian.Uint32(digest[0:4])%900000)*2
		return []int{base, base + 1}
	case KindAmneziaWG:
		base := 100000 + int(binary.BigEndian.Uint32(digest[0:4])%900000)*2
		return []int{base, base + 1}
	case KindSRv6:
		if t.Spec.SRv6 != nil && t.Spec.SRv6.RulePriority != 0 {
			return []int{t.Spec.SRv6.RulePriority}
		}
	}
	return nil
}

func AllocateSRv6RulePriority(used map[int]struct{}) (int, error) {
	for priority := SRv6AutoRulePriorityMin; priority <= SRv6AutoRulePriorityMax; priority++ {
		if _, exists := used[priority]; !exists {
			return priority, nil
		}
	}
	return 0, errors.New("no SRv6 policy-rule priorities are available")
}

func NextSRv6SourcePriority(sources []SRv6Source) int {
	used := make(map[int]struct{}, len(sources))
	highest := 0
	for _, source := range sources {
		if source.Priority >= SRv6RulePriorityMin && source.Priority <= SRv6RulePriorityMax {
			used[source.Priority] = struct{}{}
			if source.Priority > highest {
				highest = source.Priority
			}
		}
	}
	if highest < SRv6RulePriorityMax {
		return max(SRv6RulePriorityMin, highest+1)
	}
	for priority := SRv6RulePriorityMin; priority <= SRv6RulePriorityMax; priority++ {
		if _, exists := used[priority]; !exists {
			return priority
		}
	}
	return 0
}

func WireGuardRouteTable(t Tunnel, spec *WireGuardSpec) int {
	if spec.RouteTable != 0 {
		return spec.RouteTable
	}
	if wireGuardHasDefaultRoute(spec) {
		digest := sha256.Sum256([]byte(t.ID))
		return 51820 + int(binary.BigEndian.Uint16(digest[:2])%10000)
	}
	return mainRouteTable
}

// BabelManagedRealm is the engine-level route ownership tag shared by every
// route the daemon-wide Babel engine installs. It is deliberately not tied
// to a single tunnel record: a Babel route may be reached through several
// tunnels, and removing any one of them must not orphan the others.
func BabelManagedRealm() int {
	digest := sha256.Sum256([]byte("th-babel-engine"))
	return managedRouteRealmPrefix | int(binary.BigEndian.Uint32(digest[8:12])&managedRouteRealmMask)
}

func ManagedRouteClaims(t Tunnel) []RouteClaim {
	var spec *WireGuardSpec
	switch t.Kind {
	case KindWireGuard:
		spec = t.Spec.WireGuard
	case KindAmneziaWG:
		if t.Spec.AmneziaWG != nil {
			spec = &t.Spec.AmneziaWG.WireGuardSpec
		}
	}
	if spec == nil || !spec.RouteAllowedIPs {
		return nil
	}
	table := WireGuardRouteTable(t, spec)
	seen := make(map[netip.Prefix]struct{})
	claims := make([]RouteClaim, 0)
	for _, peer := range spec.Peers {
		for _, prefix := range peer.AllowedIPs {
			prefix = prefix.Masked()
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			claims = append(claims, RouteClaim{Table: table, Prefix: prefix})
		}
	}
	return claims
}

// ExclusiveRouteTables returns tables for backends that reconcile the whole
// application-owned portion of a table. Other records must not place managed
// routes in these tables because removal and stale-route cleanup are table-wide.
func ExclusiveRouteTables(t Tunnel) []int {
	if t.Kind == KindSRv6 && t.Spec.SRv6 != nil {
		return []int{t.Spec.SRv6.Table}
	}
	return nil
}

func wireGuardHasDefaultRoute(spec *WireGuardSpec) bool {
	for _, peer := range spec.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.IsValid() && prefix.Bits() == 0 {
				return true
			}
		}
	}
	return false
}
