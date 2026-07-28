package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
)

type underlayDefaults struct {
	Interface string
	Local     string
}

var findUnderlayDefaults = systemUnderlayDefaults

func systemUnderlayDefaults(remote string) underlayDefaults {
	ip := net.ParseIP(strings.TrimSpace(remote))
	if ip == nil {
		return defaultUnderlayDefaults()
	}
	return routeUnderlayDefaults(ip)
}

func defaultUnderlayDefaults() underlayDefaults {
	for _, target := range []string{"2606:4700:4700::1111", "1.1.1.1"} {
		if defaults := routeUnderlayDefaults(net.ParseIP(target)); defaults.Interface != "" {
			return defaults
		}
	}
	return underlayDefaults{}
}

func routeUnderlayDefaults(target net.IP) underlayDefaults {
	routes, err := netlink.RouteGet(target)
	if err != nil || len(routes) == 0 {
		return underlayDefaults{}
	}
	route := routes[0]
	defaults := underlayDefaults{}
	if route.Src != nil && !route.Src.IsUnspecified() {
		defaults.Local = route.Src.String()
	}
	if route.LinkIndex > 0 {
		if link, linkErr := netlink.LinkByIndex(route.LinkIndex); linkErr == nil {
			defaults.Interface = link.Attrs().Name
			if defaults.Local == "" {
				defaults.Local = firstLinkAddress(link, target)
			}
		}
	}
	return defaults
}

func firstLinkAddress(link netlink.Link, target net.IP) string {
	family := netlink.FAMILY_V6
	if target.To4() != nil {
		family = netlink.FAMILY_V4
	}
	addresses, err := netlink.AddrList(link, family)
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		if address.IP != nil && !address.IP.IsUnspecified() && !address.IP.IsLinkLocalUnicast() {
			return address.IP.String()
		}
	}
	return ""
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func addressesDefault(prompts *prompts, current string) (string, error) {
	if strings.TrimSpace(current) != "" {
		return current, nil
	}
	value := strings.TrimSpace(os.Getenv("TUNNEL_INSIDE_ADDR"))
	if value == "" {
		return current, nil
	}
	if err := validateInterfacePrefixesInput(value); err != nil {
		return "", fmt.Errorf("TUNNEL_INSIDE_ADDR: %w", err)
	}
	prompts.ui.Info("Interface addresses from TUNNEL_INSIDE_ADDR: " + value)
	return value, nil
}

func validateNewInterface(kindLabel, name string) error {
	if name == "" {
		return errors.New("interface name is required")
	}
	if err := validateInterfaceInput(name); err != nil {
		return fmt.Errorf("%s interface: %w", kindLabel, err)
	}
	if interfaceExists(name) {
		return fmt.Errorf("interface %q already exists", name)
	}
	return nil
}

func validateNewTunnelIdentity(kind model.Kind, name string, managed []model.TunnelView) error {
	candidateInterface := interfaceName(kind, name)
	for _, view := range managed {
		if view.Tunnel.Name == name {
			return fmt.Errorf("tunnel name %q is already managed", name)
		}
		if candidateInterface != "" && view.Tunnel.Interface == candidateInterface {
			return fmt.Errorf("interface %q is already managed", candidateInterface)
		}
	}
	if kind == model.KindSRv6 {
		return nil
	}
	return validateNewInterface(string(kind), candidateInterface)
}
