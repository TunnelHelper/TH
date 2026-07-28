//go:build linux

package linux

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func rulePriorities(record model.Tunnel) (int, int) {
	priorities := model.ManagedRulePriorities(record)
	if len(priorities) != 2 {
		return 0, 0
	}
	return priorities[0], priorities[1]
}

func desiredWireGuardRules(record model.Tunnel, family, table int, mark uint32) []*netlink.Rule {
	suppressPriority, markPriority := rulePriorities(record)
	suppress := netlink.NewRule()
	suppress.Family = family
	suppress.Priority = suppressPriority
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0
	suppress.Protocol = managedRouteProtocol
	mask := uint32(0xffffffff)
	marked := netlink.NewRule()
	marked.Family = family
	marked.Priority = markPriority
	marked.Table = table
	marked.Mark = mark
	marked.Mask = &mask
	marked.Invert = true
	marked.Protocol = managedRouteProtocol
	return []*netlink.Rule{suppress, marked}
}

func (b *Backend) reconcileWireGuardRules(record model.Tunnel, families map[int]bool, table int, mark uint32) error {
	suppressPriority, markPriority := rulePriorities(record)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		expected := make(map[int]*netlink.Rule)
		if families[family] {
			for _, rule := range desiredWireGuardRules(record, family, table, mark) {
				expected[rule.Priority] = rule
			}
		}
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("list policy rules: %w", err)
		}
		present := make(map[int]struct{}, len(expected))
		for i := range rules {
			if rules[i].Priority != suppressPriority && rules[i].Priority != markPriority {
				continue
			}
			want, needed := expected[rules[i].Priority]
			if rules[i].Protocol != managedRouteProtocol {
				return fmt.Errorf("policy-rule priority %d is not owned by TH: %w", rules[i].Priority, ErrOwnershipConflict)
			}
			if needed && equalManagedRule(&rules[i], want) {
				present[rules[i].Priority] = struct{}{}
				continue
			}
			if err := b.netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove stale policy rule: %w", err)
			}
		}
		for priority, rule := range expected {
			if _, ok := present[priority]; ok {
				continue
			}
			if err := b.netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("ensure WireGuard policy rule: %w", err)
			}
		}
	}
	return nil
}

func equalManagedRule(a, b *netlink.Rule) bool {
	if a.Priority != b.Priority || a.Family != b.Family || a.Table != b.Table ||
		a.Mark != b.Mark || a.Invert != b.Invert || a.SuppressPrefixlen != b.SuppressPrefixlen ||
		a.Protocol != b.Protocol {
		return false
	}
	if a.Mask == nil || b.Mask == nil {
		return a.Mask == nil && b.Mask == nil
	}
	return *a.Mask == *b.Mask
}

func (b *Backend) removeManagedRules(record model.Tunnel) error {
	suppressPriority, markPriority := rulePriorities(record)
	if suppressPriority == 0 {
		return nil
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("list policy rules: %w", err)
		}
		for i := range rules {
			if rules[i].Protocol != managedRouteProtocol || (rules[i].Priority != suppressPriority && rules[i].Priority != markPriority) {
				continue
			}
			if err := b.netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove managed policy rule: %w", err)
			}
		}
	}
	return nil
}
