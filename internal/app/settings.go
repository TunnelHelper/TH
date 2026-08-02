package app

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/config"
)

func clampExponent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 4 {
		return 4
	}
	return value
}

func validateBabelRouterIDInput(value string) error {
	if value == "" {
		return nil
	}
	settings := config.BabelSettings{RouterID: value}
	return settings.Validate()
}

func validateNonNegativeIntInput(value string) error {
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 {
		return errors.New("must be a non-negative integer")
	}
	return nil
}

func validateNonNegativeFloatInput(value string) error {
	number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || number < 0 || math.IsNaN(number) || math.IsInf(number, 0) {
		return errors.New("must be a non-negative number")
	}
	return nil
}

func validateInterfaceListInput(value string) error {
	for _, name := range splitNonEmpty(value) {
		if len(name) == 0 || len(name) > 15 || strings.ContainsAny(name, "/ \t\r\n") {
			return fmt.Errorf("invalid interface %q", name)
		}
	}
	return nil
}

func validatePrefixListInput(value string) error {
	seen := make(map[netip.Prefix]struct{})
	for _, token := range splitNonEmpty(value) {
		prefix, err := netip.ParsePrefix(token)
		if err != nil {
			return fmt.Errorf("invalid prefix %q", token)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			return fmt.Errorf("duplicate prefix %s", prefix)
		}
		seen[prefix] = struct{}{}
	}
	return nil
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func parsePrefixList(value string) []netip.Prefix {
	var result []netip.Prefix
	for _, token := range splitNonEmpty(value) {
		if prefix, err := netip.ParsePrefix(token); err == nil {
			result = append(result, prefix)
		}
	}
	return result
}

func formatPrefixList(prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		parts = append(parts, prefix.String())
	}
	return strings.Join(parts, ",")
}

func boolPtr(value bool) *bool { return &value }

func parseNeighbourList(value string) []netip.Addr {
	var result []netip.Addr
	for _, token := range splitNonEmpty(value) {
		if addr, err := netip.ParseAddr(token); err == nil {
			result = append(result, addr)
		}
	}
	return result
}

func formatNeighbourList(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, ",")
}

func validateNeighbourListInput(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("unicast mode requires at least one neighbour address")
	}
	seen := make(map[netip.Addr]struct{})
	for _, token := range splitNonEmpty(value) {
		addr, err := netip.ParseAddr(token)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() {
			return fmt.Errorf("invalid neighbour address %q", token)
		}
		if _, exists := seen[addr]; exists {
			return fmt.Errorf("duplicate neighbour address %s", addr)
		}
		seen[addr] = struct{}{}
	}
	return nil
}

func externalInterfacesSummary(interfaces map[string]config.BabelExternalInterface) string {
	if len(interfaces) == 0 {
		return "none"
	}
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		external := interfaces[name]
		mode := "multicast"
		if !external.Multicast {
			mode = "unicast (" + formatNeighbourList(external.Neighbours) + ")"
		}
		parts = append(parts, fmt.Sprintf("%s: %s, %d Mbps", name, mode, external.BandwidthMbps))
	}
	return strings.Join(parts, "; ")
}
