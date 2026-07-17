//go:build linux

package linux

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sudogeeker/tunnel-helper/internal/core"
	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const maxSRv6FeedSize = 16 << 20

type srv6Route struct {
	prefix netip.Prefix
	sid    netip.Addr
	mtu    int
}

func (b *Backend) applySRv6(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	spec := record.Spec.SRv6
	underlay, err := b.netlink.LinkByName(spec.UnderlayInterface)
	if err != nil {
		return core.Observation{}, fmt.Errorf("lookup SRv6 underlay %s: %w", spec.UnderlayInterface, err)
	}
	routes, cacheState, err := b.loadSRv6Feeds(ctx, record)
	if err != nil {
		return core.Observation{}, err
	}
	desired, err := b.buildSRv6Routes(spec, underlay, routes)
	if err != nil {
		return core.Observation{}, err
	}
	if err := b.reconcileSRv6Routes(spec.Table, desired); err != nil {
		return core.Observation{}, err
	}
	if err := b.reconcileSRv6Rules(record, spec.Table, desired); err != nil {
		return core.Observation{}, err
	}
	observation, err := b.observeSRv6(record)
	if observation.Details == nil {
		observation.Details = make(map[string]string)
	}
	observation.Details["cache"] = cacheState
	return observation, err
}

func (b *Backend) loadSRv6Feeds(ctx context.Context, record model.Tunnel) ([]srv6Route, string, error) {
	spec := record.Spec.SRv6
	cacheDir := filepath.Join(b.settings.StateDir, "cache", "srv6", record.ID)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, "", fmt.Errorf("create SRv6 cache: %w", err)
	}
	if err := os.Chmod(cacheDir, 0700); err != nil {
		return nil, "", fmt.Errorf("protect SRv6 cache: %w", err)
	}
	client := &http.Client{
		Timeout: b.settings.RequestTimeout(),
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
				return errors.New("redirected to a non-HTTP URL")
			}
			return nil
		},
	}
	allRoutes := make([]srv6Route, 0)
	usedStale := false
	for _, source := range spec.Sources {
		feeds := []struct {
			suffix string
			sid    *netip.Addr
			family int
		}{
			{suffix: "v4", sid: source.SIDv4, family: 4},
			{suffix: "v6", sid: source.SIDv6, family: 6},
		}
		for _, feed := range feeds {
			if feed.sid == nil {
				continue
			}
			filename := source.Name + "_" + feed.suffix + ".txt"
			cachePath := filepath.Join(cacheDir, filename)
			data, stale, err := fetchOrReadSRv6Feed(ctx, client, spec.BaseURL, filename, cachePath, time.Duration(spec.RefreshIntervalSeconds)*time.Second)
			if err != nil {
				return nil, "", fmt.Errorf("load SRv6 feed %s: %w", filename, err)
			}
			usedStale = usedStale || stale
			prefixes, err := parseSRv6Feed(data, feed.family)
			if err != nil {
				return nil, "", fmt.Errorf("parse SRv6 feed %s: %w", filename, err)
			}
			for _, prefix := range prefixes {
				allRoutes = append(allRoutes, srv6Route{prefix: prefix, sid: *feed.sid, mtu: source.MTU})
			}
		}
	}
	state := "fresh"
	if usedStale {
		state = "stale-fallback"
	}
	return allRoutes, state, nil
}

func fetchOrReadSRv6Feed(ctx context.Context, client *http.Client, baseURL, filename, cachePath string, refresh time.Duration) ([]byte, bool, error) {
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < refresh {
		data, err := os.ReadFile(cachePath)
		return data, false, err
	}
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return nil, false, err
	}
	reference := &url.URL{Path: filename}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.ResolveReference(reference).String(), nil)
	if err != nil {
		return nil, false, err
	}
	response, fetchErr := client.Do(request)
	if fetchErr == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			fetchErr = fmt.Errorf("HTTP status %d", response.StatusCode)
		} else if response.ContentLength > maxSRv6FeedSize {
			fetchErr = errors.New("feed exceeds size limit")
		} else {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, maxSRv6FeedSize+1))
			if readErr != nil {
				fetchErr = readErr
			} else if len(data) > maxSRv6FeedSize {
				fetchErr = errors.New("feed exceeds size limit")
			} else if err := writeCacheAtomic(cachePath, data); err != nil {
				fetchErr = err
			} else {
				return data, false, nil
			}
		}
	}
	cached, cacheErr := os.ReadFile(cachePath)
	if cacheErr == nil {
		return cached, true, nil
	}
	return nil, false, errors.Join(fetchErr, cacheErr)
}

func writeCacheAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".feed-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	committed = true
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func parseSRv6Feed(data []byte, family int) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0)
	seen := make(map[netip.Prefix]struct{})
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if (family == 4) != prefix.Addr().Is4() {
			return nil, fmt.Errorf("line %d has the wrong address family", lineNumber)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (b *Backend) buildSRv6Routes(spec *model.SRv6Spec, underlay netlink.Link, routes []srv6Route) ([]netlink.Route, error) {
	desired := make([]netlink.Route, 0, len(routes)+len(spec.Sources)*2)
	sids := make(map[netip.Addr]struct{})
	for _, route := range routes {
		sids[route.sid] = struct{}{}
		desired = append(desired, netlink.Route{
			LinkIndex: underlay.Attrs().Index,
			Dst:       prefixToIPNet(route.prefix),
			Table:     spec.Table,
			Protocol:  managedRouteProtocol,
			Scope:     netlink.SCOPE_UNIVERSE,
			MTU:       route.mtu,
			Encap: &netlink.SEG6Encap{
				Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
				Segments: []net.IP{ipFromAddr(route.sid)},
			},
		})
	}
	defaultRoute, err := b.defaultRoute(netlink.FAMILY_V6, underlay.Attrs().Index)
	if err != nil {
		return nil, err
	}
	for sid := range sids {
		route := netlink.Route{
			LinkIndex: underlay.Attrs().Index,
			Dst:       prefixToIPNet(netip.PrefixFrom(sid, 128)),
			Table:     spec.Table,
			Protocol:  managedRouteProtocol,
			Scope:     netlink.SCOPE_LINK,
		}
		if defaultRoute != nil && len(defaultRoute.Gw) > 0 {
			route.Gw = defaultRoute.Gw
			route.Scope = netlink.SCOPE_UNIVERSE
			route.Flags = int(netlink.FLAG_ONLINK)
		}
		desired = append(desired, route)
	}
	return desired, nil
}

func (b *Backend) defaultRoute(family, linkIndex int) (*netlink.Route, error) {
	routes, err := b.netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list main-table routes: %w", err)
	}
	var selected *netlink.Route
	for i := range routes {
		if routes[i].LinkIndex != linkIndex || (routes[i].Dst != nil && maskSize(routes[i].Dst) != 0) {
			continue
		}
		if selected == nil || routes[i].Priority < selected.Priority {
			copy := routes[i]
			selected = &copy
		}
	}
	return selected, nil
}

func maskSize(network *net.IPNet) int {
	ones, _ := network.Mask.Size()
	return ones
}

func (b *Backend) reconcileSRv6Routes(table int, desired []netlink.Route) error {
	current, err := b.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list SRv6 route table %d: %w", table, err)
	}
	wanted := make(map[string]netlink.Route, len(desired))
	for _, route := range desired {
		key := routeKey(route)
		if previous, ok := wanted[key]; ok && !equalManagedRoute(previous, route) {
			return fmt.Errorf("SRv6 sources define conflicting routes for %s", key)
		}
		wanted[key] = route
	}
	for key, route := range wanted {
		matched := false
		for _, existing := range current {
			if routeKey(existing) != key {
				continue
			}
			if existing.Protocol != managedRouteProtocol {
				return fmt.Errorf("route %s in table %d has protocol %d: %w", key, table, existing.Protocol, ErrOwnershipConflict)
			}
			if equalManagedRoute(existing, route) {
				matched = true
			}
		}
		if !matched {
			if err := b.netlink.RouteReplace(&route); err != nil {
				return fmt.Errorf("ensure SRv6 route %s: %w", key, err)
			}
		}
	}
	for i := range current {
		if current[i].Protocol != managedRouteProtocol {
			continue
		}
		if _, ok := wanted[routeKey(current[i])]; ok {
			continue
		}
		if err := b.netlink.RouteDel(&current[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("remove stale SRv6 route: %w", err)
		}
	}
	return nil
}

func equalManagedRoute(a, b netlink.Route) bool {
	if routeKey(a) != routeKey(b) || a.LinkIndex != b.LinkIndex || a.Protocol != b.Protocol || a.Scope != b.Scope ||
		a.MTU != b.MTU || a.Flags != b.Flags || !a.Gw.Equal(b.Gw) {
		return false
	}
	aSEG6, aOK := a.Encap.(*netlink.SEG6Encap)
	bSEG6, bOK := b.Encap.(*netlink.SEG6Encap)
	if aOK != bOK {
		return false
	}
	if !aOK {
		return true
	}
	if aSEG6.Mode != bSEG6.Mode || len(aSEG6.Segments) != len(bSEG6.Segments) {
		return false
	}
	for i := range aSEG6.Segments {
		if !aSEG6.Segments[i].Equal(bSEG6.Segments[i]) {
			return false
		}
	}
	return true
}

func routeKey(route netlink.Route) string {
	return fmt.Sprintf("%d|%s", route.Table, routeDestinationKey(route))
}

func srv6RulePriority(record model.Tunnel) int {
	priorities := model.ManagedRulePriorities(record)
	if len(priorities) != 1 {
		return 0
	}
	return priorities[0]
}

func (b *Backend) reconcileSRv6Rules(record model.Tunnel, table int, routes []netlink.Route) error {
	families := make(map[int]struct{})
	for _, route := range routes {
		family := netlink.FAMILY_V6
		if route.Dst != nil && route.Dst.IP.To4() != nil {
			family = netlink.FAMILY_V4
		}
		families[family] = struct{}{}
	}
	priority := srv6RulePriority(record)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return err
		}
		present := false
		for i := range rules {
			rule := &rules[i]
			if rule.Priority != priority {
				continue
			}
			if rule.Protocol != managedRouteProtocol {
				return fmt.Errorf("policy rule priority %d is already used: %w", priority, ErrOwnershipConflict)
			}
			_, needed := families[family]
			if needed && rule.Table == table {
				present = true
				continue
			}
			if err := b.netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove stale SRv6 policy rule: %w", err)
			}
		}
		if _, needed := families[family]; !needed || present {
			continue
		}
		rule := netlink.NewRule()
		rule.Family = family
		rule.Priority = priority
		rule.Table = table
		rule.Protocol = managedRouteProtocol
		if err := b.netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("ensure SRv6 policy rule: %w", err)
		}
	}
	return nil
}

func (b *Backend) removeSRv6(record model.Tunnel) error {
	spec := record.Spec.SRv6
	if spec == nil {
		return nil
	}
	routes, err := b.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: spec.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for i := range routes {
		if routes[i].Protocol == managedRouteProtocol {
			if err := b.netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	priority := srv6RulePriority(record)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return err
		}
		for i := range rules {
			if rules[i].Protocol == managedRouteProtocol && rules[i].Priority == priority && rules[i].Table == spec.Table {
				if err := b.netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
					return err
				}
			}
		}
	}
	return nil
}

func (b *Backend) observeSRv6(record model.Tunnel) (core.Observation, error) {
	spec := record.Spec.SRv6
	routes, err := b.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: spec.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return core.Observation{}, err
	}
	managed := 0
	for _, route := range routes {
		if route.Protocol == managedRouteProtocol {
			managed++
		}
	}
	return core.Observation{Details: map[string]string{
		"table":          strconv.Itoa(spec.Table),
		"managed_routes": strconv.Itoa(managed),
	}}, nil
}
