//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	maxSRv6FeedSize      = 16 << 20
	maxSRv6RoutesPerFeed = 65536
	maxSRv6RoutesTotal   = 262144
)

type srv6Route struct {
	prefix   netip.Prefix
	sid      netip.Addr
	mtu      int
	priority int
}

func (b *Backend) applySRv6(ctx context.Context, record model.Tunnel) (core.Observation, error) {
	spec := record.Spec.SRv6
	underlay, err := b.netlink.LinkByName(spec.UnderlayInterface)
	if err != nil {
		return core.Observation{}, fmt.Errorf("lookup SRv6 underlay %s: %w", spec.UnderlayInterface, err)
	}
	routes, cacheState, skippedPrefixes, err := b.loadSRv6Feeds(ctx, record)
	if err != nil {
		return core.Observation{}, err
	}
	desired, err := b.buildSRv6Routes(record, underlay, routes)
	if err != nil {
		return core.Observation{}, err
	}
	if err := b.reconcileSRv6Routes(record, desired); err != nil {
		return core.Observation{}, err
	}
	if err := b.reconcileSRv6Rules(record, spec.Table, desired); err != nil {
		return core.Observation{}, err
	}
	observation, err := b.observeSRv6Desired(record, desired)
	if observation.Details == nil {
		observation.Details = make(map[string]string)
	}
	observation.Details["cache"] = cacheState
	observation.Details["skipped_prefixes"] = strconv.Itoa(skippedPrefixes)
	return observation, err
}

func (b *Backend) loadSRv6Feeds(ctx context.Context, record model.Tunnel) ([]srv6Route, string, int, error) {
	spec := record.Spec.SRv6
	cacheDir := filepath.Join(b.settings.StateDir, "cache", "srv6", record.ID)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, "", 0, fmt.Errorf("create SRv6 cache: %w", err)
	}
	if err := os.Chmod(cacheDir, 0700); err != nil {
		return nil, "", 0, fmt.Errorf("protect SRv6 cache: %w", err)
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
	sources := append([]model.SRv6Source(nil), spec.Sources...)
	sort.SliceStable(sources, func(i, j int) bool {
		return sources[i].Priority < sources[j].Priority
	})
	for _, source := range sources {
		family := 0
		switch source.Family {
		case model.SRv6FamilyIPv4:
			family = 4
		case model.SRv6FamilyIPv6:
			family = 6
		default:
			return nil, "", 0, fmt.Errorf("load SRv6 feed %s: unsupported address family %q", source.Name, source.Family)
		}
		familyName := string(source.Family)
		filename := srv6FeedCacheFilename(source.Name, familyName, source.PrefixURL)
		cachePath := filepath.Join(cacheDir, filename)
		data, stale, err := fetchOrReadSRv6Feed(ctx, client, source.PrefixURL, cachePath, time.Duration(spec.RefreshIntervalSeconds)*time.Second)
		if err != nil {
			return nil, "", 0, fmt.Errorf("load SRv6 feed %s/%s: %w", source.Name, familyName, err)
		}
		usedStale = usedStale || stale
		prefixes, err := parseSRv6Feed(data, family)
		if err != nil {
			return nil, "", 0, fmt.Errorf("parse SRv6 feed %s/%s: %w", source.Name, familyName, err)
		}
		if len(allRoutes)+len(prefixes) > maxSRv6RoutesTotal {
			return nil, "", 0, fmt.Errorf("SRv6 feeds exceed %d total routes", maxSRv6RoutesTotal)
		}
		for _, prefix := range prefixes {
			allRoutes = append(allRoutes, srv6Route{
				prefix: prefix, sid: source.SID, mtu: source.MTU, priority: source.Priority,
			})
		}
	}
	state := "fresh"
	if usedStale {
		state = "stale-fallback"
	}
	resolved, skipped := resolveSRv6RouteConflicts(allRoutes)
	return resolved, state, skipped, nil
}

func srv6FeedCacheFilename(sourceName, family, feedURL string) string {
	digest := sha256.Sum256([]byte(feedURL))
	return fmt.Sprintf("%s_%s_%x.txt", sourceName, family, digest[:8])
}

func fetchOrReadSRv6Feed(ctx context.Context, client *http.Client, feedURL, cachePath string, refresh time.Duration) ([]byte, bool, error) {
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < refresh {
		data, err := os.ReadFile(cachePath)
		return data, false, err
	}
	parsed, err := url.Parse(feedURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, false, errors.New("feed URL must be an absolute HTTP or HTTPS URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
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

func resolveSRv6RouteConflicts(routes []srv6Route) ([]srv6Route, int) {
	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].priority < routes[j].priority
	})
	selected := make(map[netip.Prefix]srv6Route, len(routes))
	result := make([]srv6Route, 0, len(routes))
	skipped := 0
	for _, route := range routes {
		_, exists := selected[route.prefix]
		if !exists {
			selected[route.prefix] = route
			result = append(result, route)
			continue
		}
		skipped++
	}
	return result, skipped
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
	scanner := bufio.NewScanner(bytes.NewReader(data))
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
		if len(result) >= maxSRv6RoutesPerFeed {
			return nil, fmt.Errorf("feed exceeds %d unique routes", maxSRv6RoutesPerFeed)
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (b *Backend) buildSRv6Routes(record model.Tunnel, underlay netlink.Link, routes []srv6Route) ([]netlink.Route, error) {
	spec := record.Spec.SRv6
	realm := model.ManagedRouteRealm(record)
	desired := make([]netlink.Route, 0, len(routes)+len(spec.Sources)*2)
	sids := make(map[netip.Addr]struct{})
	for _, route := range routes {
		sids[route.sid] = struct{}{}
		desired = append(desired, netlink.Route{
			LinkIndex: underlay.Attrs().Index,
			Dst:       prefixToIPNet(route.prefix),
			Table:     spec.Table,
			Protocol:  managedRouteProtocol,
			Realm:     realm,
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
			Realm:     realm,
			Scope:     netlink.SCOPE_UNIVERSE,
			Priority:  1024,
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

func (b *Backend) reconcileSRv6Routes(record model.Tunnel, desired []netlink.Route) error {
	table := record.Spec.SRv6.Table
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
	currentByKey := make(map[string][]netlink.Route, len(current))
	for _, route := range current {
		key := routeKey(route)
		currentByKey[key] = append(currentByKey[key], route)
	}
	for key, route := range wanted {
		matched := false
		for _, existing := range currentByKey[key] {
			if !routeOwnedByRecord(record, existing) && !(existing.Protocol == managedRouteProtocol && existing.Realm == 0) {
				return fmt.Errorf("route %s in table %d is not owned by TH: %w", key, table, ErrOwnershipConflict)
			}
			if equalSRv6ManagedRoute(existing, route) {
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
		if !routeOwnedByRecord(record, current[i]) {
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
	if routeKey(a) != routeKey(b) || a.LinkIndex != b.LinkIndex || a.Protocol != b.Protocol || a.Realm != b.Realm || a.Scope != b.Scope ||
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

func equalSRv6ManagedRoute(current, desired netlink.Route) bool {
	if current.Realm == 0 && desired.Realm != 0 && srv6RouteHasIPv6Destination(current) {
		desired.Realm = 0
	}
	return equalManagedRoute(current, desired)
}

func srv6RouteHasIPv6Destination(route netlink.Route) bool {
	prefix, ok := prefixFromIPNet(route.Dst)
	return ok && prefix.Addr().Is6()
}

func srv6RouteOwnedForDesired(record model.Tunnel, route netlink.Route, desired map[string]netlink.Route) bool {
	if routeOwnedByRecord(record, route) {
		return true
	}
	if route.Protocol != managedRouteProtocol || route.Realm != 0 || !srv6RouteHasIPv6Destination(route) {
		return false
	}
	_, expected := desired[routeKey(route)]
	return expected
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
				if rule.Protocol == managedRouteProtocol && rule.Table == table {
					if err := b.netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) {
						return fmt.Errorf("remove legacy SRv6 policy rule: %w", err)
					}
				}
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
	desired := b.cachedSRv6RemovalRoutes(record)
	for i := range routes {
		if routeOwnedByRecord(record, routes[i]) || srv6RouteOwnedForDesired(record, routes[i], desired) {
			if err := b.netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := b.netlink.RuleList(family)
		if err != nil {
			return err
		}
		for i := range rules {
			if rules[i].Protocol == managedRouteProtocol && rules[i].Table == spec.Table {
				if err := b.netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
					return err
				}
			}
		}
	}
	return nil
}

func (b *Backend) cachedSRv6RemovalRoutes(record model.Tunnel) map[string]netlink.Route {
	spec := record.Spec.SRv6
	desired := make(map[string]netlink.Route, len(spec.Sources)*2)
	for _, source := range spec.Sources {
		route := netlink.Route{Table: spec.Table, Dst: prefixToIPNet(netip.PrefixFrom(source.SID, 128))}
		desired[routeKey(route)] = route
	}
	cached, _, err := b.loadCachedSRv6Feeds(record)
	if err != nil {
		return desired
	}
	for _, route := range cached {
		netlinkRoute := netlink.Route{Table: spec.Table, Dst: prefixToIPNet(route.prefix)}
		desired[routeKey(netlinkRoute)] = netlinkRoute
	}
	return desired
}

func (b *Backend) loadCachedSRv6Feeds(record model.Tunnel) ([]srv6Route, int, error) {
	spec := record.Spec.SRv6
	cacheDir := filepath.Join(b.settings.StateDir, "cache", "srv6", record.ID)
	sources := append([]model.SRv6Source(nil), spec.Sources...)
	sort.SliceStable(sources, func(i, j int) bool {
		return sources[i].Priority < sources[j].Priority
	})
	allRoutes := make([]srv6Route, 0)
	for _, source := range sources {
		family := 0
		switch source.Family {
		case model.SRv6FamilyIPv4:
			family = 4
		case model.SRv6FamilyIPv6:
			family = 6
		default:
			return nil, 0, fmt.Errorf("unsupported address family %q", source.Family)
		}
		cachePath := filepath.Join(cacheDir, srv6FeedCacheFilename(source.Name, string(source.Family), source.PrefixURL))
		data, err := os.ReadFile(cachePath)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: cached feed %s/%s is unavailable: %v", core.ErrDriftDetected, source.Name, source.Family, err)
		}
		prefixes, err := parseSRv6Feed(data, family)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: cached feed %s/%s is invalid: %v", core.ErrDriftDetected, source.Name, source.Family, err)
		}
		if len(allRoutes)+len(prefixes) > maxSRv6RoutesTotal {
			return nil, 0, fmt.Errorf("cached SRv6 feeds exceed %d total routes", maxSRv6RoutesTotal)
		}
		for _, prefix := range prefixes {
			allRoutes = append(allRoutes, srv6Route{
				prefix: prefix, sid: source.SID, mtu: source.MTU, priority: source.Priority,
			})
		}
	}
	resolved, skipped := resolveSRv6RouteConflicts(allRoutes)
	return resolved, skipped, nil
}

func (b *Backend) observeSRv6(record model.Tunnel) (core.Observation, error) {
	if !record.Enabled {
		return b.observeSRv6Desired(record, nil)
	}
	underlay, err := b.netlink.LinkByName(record.Spec.SRv6.UnderlayInterface)
	if err != nil {
		return core.Observation{}, fmt.Errorf("%w: lookup SRv6 underlay %s: %v", core.ErrDriftDetected, record.Spec.SRv6.UnderlayInterface, err)
	}
	routes, skipped, err := b.loadCachedSRv6Feeds(record)
	if err != nil {
		return core.Observation{}, err
	}
	desired, err := b.buildSRv6Routes(record, underlay, routes)
	if err != nil {
		return core.Observation{}, err
	}
	observation, observeErr := b.observeSRv6Desired(record, desired)
	if observation.Details == nil {
		observation.Details = make(map[string]string)
	}
	observation.Details["skipped_prefixes"] = strconv.Itoa(skipped)
	return observation, observeErr
}

func (b *Backend) observeSRv6Desired(record model.Tunnel, desired []netlink.Route) (core.Observation, error) {
	spec := record.Spec.SRv6
	routes, err := b.netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: spec.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return core.Observation{}, err
	}
	wanted := make(map[string]netlink.Route, len(desired))
	for _, route := range desired {
		wanted[routeKey(route)] = route
	}
	ownershipDesired := wanted
	if len(wanted) == 0 {
		ownershipDesired = b.cachedSRv6RemovalRoutes(record)
	}
	currentByKey := make(map[string][]netlink.Route, len(routes))
	managed, missing, mismatched, stale, conflicts := 0, 0, 0, 0, 0
	for _, route := range routes {
		currentByKey[routeKey(route)] = append(currentByKey[routeKey(route)], route)
		if srv6RouteOwnedForDesired(record, route, ownershipDesired) {
			managed++
		}
	}
	for key, route := range wanted {
		owned, exact, foreign := 0, 0, 0
		for _, current := range currentByKey[key] {
			if !srv6RouteOwnedForDesired(record, current, wanted) {
				foreign++
				continue
			}
			owned++
			if equalSRv6ManagedRoute(current, route) {
				exact++
			}
		}
		if exact == 0 {
			if owned == 0 {
				missing++
			} else {
				mismatched++
			}
		}
		if owned > 1 {
			stale += owned - 1
		}
		conflicts += foreign
	}
	for _, route := range routes {
		if !srv6RouteOwnedForDesired(record, route, ownershipDesired) {
			continue
		}
		if _, expected := wanted[routeKey(route)]; !expected {
			stale++
		}
	}

	families := desiredSRv6Families(desired)
	expectedRules, presentRules, missingRules, staleRules := len(families), 0, 0, 0
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, listErr := b.netlink.RuleList(family)
		if listErr != nil {
			return core.Observation{}, listErr
		}
		_, needed := families[family]
		present := false
		for i := range rules {
			rule := &rules[i]
			if rule.Protocol == managedRouteProtocol && rule.Table == spec.Table && rule.Priority != spec.RulePriority {
				staleRules++
				continue
			}
			if rule.Priority != spec.RulePriority {
				continue
			}
			if rule.Protocol == managedRouteProtocol && needed && rule.Table == spec.Table && !present {
				present = true
				presentRules++
				continue
			}
			staleRules++
		}
		if needed && !present {
			missingRules++
		}
	}
	details := map[string]string{
		"table":                 strconv.Itoa(spec.Table),
		"rule_priority":         strconv.Itoa(spec.RulePriority),
		"managed_routes":        strconv.Itoa(managed),
		"expected_routes":       strconv.Itoa(len(desired)),
		"route_conflicts":       strconv.Itoa(conflicts),
		"policy_rules":          strconv.Itoa(presentRules),
		"expected_policy_rules": strconv.Itoa(expectedRules),
	}
	observation := core.Observation{Details: details}
	if spec.RulePriority >= model.MainRulePriority {
		return observation, fmt.Errorf("%w: SRv6 policy-rule priority %d does not precede main priority %d", core.ErrDriftDetected, spec.RulePriority, model.MainRulePriority)
	}
	if missing != 0 || mismatched != 0 || stale != 0 || conflicts != 0 || missingRules != 0 || staleRules != 0 {
		return observation, fmt.Errorf(
			"%w: SRv6 routes missing=%d mismatched=%d stale=%d conflicts=%d; policy rules missing=%d stale=%d",
			core.ErrDriftDetected, missing, mismatched, stale, conflicts, missingRules, staleRules,
		)
	}
	return observation, nil
}

func desiredSRv6Families(routes []netlink.Route) map[int]struct{} {
	families := make(map[int]struct{})
	for _, route := range routes {
		family := netlink.FAMILY_V6
		if route.Dst != nil && route.Dst.IP.To4() != nil {
			family = netlink.FAMILY_V4
		}
		families[family] = struct{}{}
	}
	return families
}
