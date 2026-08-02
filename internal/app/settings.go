package app

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/ui"
)

// editDaemonSettings edits the daemon-global Babel and MPTCP settings
// through the local API and persists them.
func (a *tuiApp) editDaemonSettings() error {
	ctx, cancel := a.context()
	settings, err := a.client.Settings(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("load Babel settings: %w", err)
	}
	if err := a.manageExternalBabelInterfaces(&settings.Babel); err != nil {
		return err
	}

	if err := a.prompts.input("Router ID (16 hex chars, empty = generated)", &settings.Babel.RouterID, validateBabelRouterIDInput); err != nil {
		return err
	}
	delayMetric := "Enabled"
	if !settings.Babel.DelayMetricEnabled() {
		delayMetric = "Disabled"
	}
	if err := a.prompts.selectValue("Delay-based cost (RFC 9616)", []ui.Option{
		{Label: "Enabled", Value: "Enabled"},
		{Label: "Disabled", Value: "Disabled"},
	}, &delayMetric); err != nil {
		return err
	}
	settings.Babel.DelayMetric = boolPtr(delayMetric == "Enabled")

	// ECMP balance knob: bias in [-2, 2] maps to the weight exponents
	// (alpha = 1 + bias, beta = 1 - bias, clamped to [0, 4]). Moving left
	// favours low latency, moving right favours bandwidth; the centre is
	// the default (1, 1). Stored exponents that are not representable on
	// the balance line (alpha + beta != 2) are preserved unless the user
	// actually moves the knob, so an unrelated save never rewrites them.
	origAlpha, origBeta := settings.Babel.WeightBandwidthExponent, settings.Babel.WeightRTTExponent
	bias := balanceBias(origAlpha, origBeta)
	initialBias := bias
	if !exponentsRepresentable(origAlpha, origBeta) {
		a.ui.Warn(fmt.Sprintf("Stored weight exponents α=%.2f β=%.2f are not on the balance line (α+β=2); they are kept unless you move the slider.", origAlpha, origBeta))
	}
	if err := a.prompts.slider("ECMP balance (right = bandwidth, left = latency)", -2, 2, 1, &bias, func(value float64) string {
		return renderBalanceSlider(value, origAlpha, origBeta)
	}); err != nil {
		return err
	}
	settings.Babel.WeightBandwidthExponent, settings.Babel.WeightRTTExponent = balanceExponents(bias != initialBias, bias, origAlpha, origBeta)

	routeTable := strconv.Itoa(settings.Babel.RouteTable)
	if err := a.prompts.input("Route table (0 = main)", &routeTable, validateInt(0, math.MaxInt32)); err != nil {
		return err
	}
	settings.Babel.RouteTable, _ = strconv.Atoi(routeTable)

	helloSeconds := strconv.Itoa(settings.Babel.UnicastHelloSeconds)
	if err := a.prompts.input("Unicast Hello seconds (0 = default 4)", &helloSeconds, validateInt(0, 3600)); err != nil {
		return err
	}
	settings.Babel.UnicastHelloSeconds, _ = strconv.Atoi(helloSeconds)

	maxPaths := strconv.Itoa(settings.Babel.MultipathMaxPaths)
	if err := a.prompts.input("Max ECMP paths (0 = default 4)", &maxPaths, validateInt(0, 8)); err != nil {
		return err
	}
	settings.Babel.MultipathMaxPaths, _ = strconv.Atoi(maxPaths)

	slack := strconv.Itoa(settings.Babel.MultipathSlack)
	if err := a.prompts.input("Multipath cost slack (0 = equal cost only)", &slack, validateInt(0, 65534)); err != nil {
		return err
	}
	settings.Babel.MultipathSlack, _ = strconv.Atoi(slack)

	kPenalty := strconv.FormatFloat(settings.Babel.WeightBottleneckPenalty, 'g', -1, 64)
	if err := a.prompts.input("Bottleneck penalty K (0 = delay-only primary path)", &kPenalty, validateNonNegativeFloatInput); err != nil {
		return err
	}
	if value, err := strconv.ParseFloat(strings.TrimSpace(kPenalty), 64); err == nil {
		settings.Babel.WeightBottleneckPenalty = value
	}

	sources := strings.Join(settings.Babel.Advertise.SourceInterfaces, ",")
	if err := a.prompts.input("Advertise source interfaces (comma separated)", &sources, validateInterfaceListInput); err != nil {
		return err
	}
	settings.Babel.Advertise.SourceInterfaces = splitNonEmpty(sources)

	explicit := formatPrefixList(settings.Babel.Advertise.AdvertisedPrefixes)
	if err := a.prompts.input("Explicit advertised prefixes (empty = discover)", &explicit, validatePrefixListInput); err != nil {
		return err
	}
	settings.Babel.Advertise.AdvertisedPrefixes = parsePrefixList(explicit)

	include := formatPrefixList(settings.Babel.Advertise.Include)
	if err := a.prompts.input("Include filter (empty = allow all)", &include, validatePrefixListInput); err != nil {
		return err
	}
	settings.Babel.Advertise.Include = parsePrefixList(include)

	exclude := formatPrefixList(settings.Babel.Advertise.Exclude)
	if err := a.prompts.input("Exclude filter", &exclude, validatePrefixListInput); err != nil {
		return err
	}
	settings.Babel.Advertise.Exclude = parsePrefixList(exclude)

	if err := a.editMptcpSection(&settings.Mptcp); err != nil {
		return err
	}

	if err := settings.Validate(); err != nil {
		return fmt.Errorf("invalid daemon settings: %w", err)
	}
	proceed, err := a.prompts.confirmAction("Save Babel and MPTCP settings?", "Save")
	if err != nil || !proceed {
		return err
	}

	ctx, cancel = a.context()
	defer cancel()
	if err := a.client.UpdateSettings(ctx, settings); err != nil {
		return fmt.Errorf("update daemon settings: %w", err)
	}
	a.ui.Info("Babel and MPTCP settings saved")
	return nil
}

// editMptcpSection edits the daemon-global MPTCP switch and scheduler. The
// section is read-only about kernel capability: TH never blocks a save,
// but the operator sees why MPTCP is not effective when it is unsupported.
func (a *tuiApp) editMptcpSection(settings *config.MptcpSettings) error {
	ctx, cancel := a.context()
	health, healthErr := a.client.Health(ctx)
	cancel()
	if healthErr != nil {
		return fmt.Errorf("load daemon health: %w", healthErr)
	}
	a.ui.Info(fmt.Sprintf("MPTCP: %s, TH-managed endpoints: %d", health.Mptcp.Status, health.Mptcp.Endpoints))
	a.ui.Info("MPTCP aggregation depends on the number of subflows the kernel creates; TH manages endpoints only, not per-flow aggregation.")
	if !health.Mptcp.Supported && health.Mptcp.Message != "" {
		a.ui.Warn(fmt.Sprintf("MPTCP is not available on this kernel: %s", health.Mptcp.Message))
	}

	enabled := "No"
	if settings.Enabled {
		enabled = "Yes"
	}
	if err := a.prompts.selectValue("MPTCP endpoint management (default off)", []ui.Option{
		{Label: "No", Value: "No"},
		{Label: "Yes", Value: "Yes"},
	}, &enabled); err != nil {
		return err
	}
	settings.Enabled = enabled == "Yes"

	schedulerOptions := []ui.Option{
		{Label: "Leave system default", Value: ""},
	}
	for _, scheduler := range config.KnownMPTCPSchedulers {
		schedulerOptions = append(schedulerOptions, ui.Option{Label: scheduler, Value: scheduler})
	}
	if err := a.prompts.selectValue("MPTCP scheduler (node-global, affects all MPTCP traffic)", schedulerOptions, &settings.Scheduler); err != nil {
		return err
	}
	return nil
}

// balanceBias converts the stored weight exponents to the slider position.
// It is the inverse of the write-back mapping (alpha = 1 + bias,
// beta = 1 - bias), so the dialog round-trips for pairs with
// alpha + beta = 2 and otherwise preserves the bandwidth/latency direction.
func balanceBias(alpha, beta float64) float64 {
	bias := (alpha - beta) / 2
	if bias < -2 {
		return -2
	}
	if bias > 2 {
		return 2
	}
	return bias
}

// exponentsRepresentable reports whether the stored weight exponents can be
// expressed exactly by the slider mapping (alpha = 1 + bias, beta = 1 -
// bias), i.e. whether alpha + beta = 2 within floating-point tolerance.
func exponentsRepresentable(alpha, beta float64) bool {
	return math.Abs(alpha+beta-2) < 1e-9
}

// balanceExponents applies the slider result to the stored exponents. When
// the knob was not moved, the stored exponents are preserved verbatim so an
// unrepresentable pair is never silently rewritten by an unrelated save.
func balanceExponents(moved bool, bias, storedAlpha, storedBeta float64) (float64, float64) {
	if !moved {
		return storedAlpha, storedBeta
	}
	return clampExponent(1 + bias), clampExponent(1 - bias)
}

// renderBalanceSlider draws the bandwidth/latency balance knob.
// While the knob sits on the stored position of an unrepresentable pair,
// the readout shows the stored exponents instead of the derived ones, so
// the dialog never misrepresents what a save will persist.
func renderBalanceSlider(value, storedAlpha, storedBeta float64) string {
	const positions = 21
	index := int(math.Round((value + 2) / 4 * float64(positions-1)))
	bar := strings.Repeat("─", index) + "●" + strings.Repeat("─", positions-1-index)
	alpha := math.Max(0, 1+value)
	beta := math.Max(0, 1-value)
	if value == balanceBias(storedAlpha, storedBeta) && !exponentsRepresentable(storedAlpha, storedBeta) {
		return fmt.Sprintf("Latency ◄ %s ► Bandwidth    α=%.2f β=%.2f (stored)", bar, storedAlpha, storedBeta)
	}
	return fmt.Sprintf("Latency ◄ %s ► Bandwidth    α=%.1f β=%.1f", bar, alpha, beta)
}

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
	for _, token := range splitNonEmpty(value) {
		if _, err := netip.ParsePrefix(token); err != nil {
			return fmt.Errorf("invalid prefix %q", token)
		}
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

// manageExternalBabelInterfaces offers add/edit/remove for the external
// point-to-point interfaces declared in babel.interfaces. Interfaces are
// picked from the system's real interfaces with a keyword filter.
func (a *tuiApp) manageExternalBabelInterfaces(settings *config.BabelSettings) error {
	if settings.Interfaces == nil {
		settings.Interfaces = make(map[string]config.BabelExternalInterface)
	}
	ctx, cancel := a.context()
	views, err := a.client.List(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("list tunnels: %w", err)
	}
	usedByTunnels := make(map[string]bool, len(views))
	for _, view := range views {
		if view.Tunnel.Interface != "" {
			usedByTunnels[view.Tunnel.Interface] = true
		}
	}

	for {
		a.ui.Info("External Babel interfaces: " + externalInterfacesSummary(settings.Interfaces))
		action := "done"
		if err := a.prompts.selectValue("Manage external Babel interfaces", []ui.Option{
			{Label: "Add interface", Value: "add"},
			{Label: "Edit interface", Value: "edit"},
			{Label: "Remove interface", Value: "remove", Destructive: true},
			{Label: "Done", Value: "done"},
		}, &action); err != nil {
			return err
		}

		switch action {
		case "done":
			return nil
		case "add":
			exclude := make(map[string]bool, len(settings.Interfaces))
			for name := range settings.Interfaces {
				exclude[name] = true
			}
			name, err := a.prompts.selectSystemInterface("Add external Babel interface", exclude, usedByTunnels)
			if err != nil {
				return err
			}
			if name == "" {
				continue
			}
			external, err := collectExternalInterface(a.prompts, name, nil)
			if err != nil {
				return err
			}
			settings.Interfaces[name] = external
		case "edit":
			if len(settings.Interfaces) == 0 {
				a.ui.Warn("No external Babel interfaces configured yet")
				continue
			}
			name := firstExternalInterface(settings.Interfaces)
			if err := a.prompts.selectValue("Edit external interface", externalInterfaceOptions(settings.Interfaces), &name); err != nil {
				return err
			}
			existing := settings.Interfaces[name]
			updated, err := collectExternalInterface(a.prompts, name, &existing)
			if err != nil {
				return err
			}
			settings.Interfaces[name] = updated
		case "remove":
			if len(settings.Interfaces) == 0 {
				a.ui.Warn("No external Babel interfaces configured yet")
				continue
			}
			name := firstExternalInterface(settings.Interfaces)
			if err := a.prompts.selectValue("Remove external interface", externalInterfaceOptions(settings.Interfaces), &name); err != nil {
				return err
			}
			proceed, err := a.prompts.confirmAction(fmt.Sprintf("Remove external Babel interface %s?", name), "Remove")
			if err != nil {
				return err
			}
			if proceed {
				delete(settings.Interfaces, name)
			}
		}
	}
}

// selectSystemInterface reads the host's real interfaces and lets the user
// narrow them with a keyword before selecting one. Already-configured
// external interfaces and TH-managed tunnel interfaces are marked (the
// latter cannot be selected as external interfaces; the daemon rejects
// them). An empty selection means the user cancelled.
func (p *prompts) selectSystemInterface(title string, exclude map[string]bool, usedByTunnels map[string]bool) (string, error) {
	intfs, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list system interfaces: %w", err)
	}
	for {
		keyword := ""
		if err := p.input("Filter interfaces (keyword, empty = all)", &keyword, nil); err != nil {
			return "", err
		}
		options := systemInterfaceOptions(intfs, keyword, exclude, usedByTunnels)
		if len(options) == 0 {
			p.ui.Warn("No interfaces match this keyword")
			continue
		}
		options = append(options, ui.Option{Label: "Cancel", Value: ""})
		selected := ""
		if err := p.selectValue(title, options, &selected); err != nil {
			return "", err
		}
		return selected, nil
	}
}

// systemInterfaceOptions builds the selectable options from the host's
// interfaces, excluding loopback and names already configured as external
// Babel interfaces, and filtering by a case-insensitive keyword.
func systemInterfaceOptions(intfs []net.Interface, keyword string, exclude map[string]bool, usedByTunnels map[string]bool) []ui.Option {
	options := make([]ui.Option, 0, len(intfs))
	for _, intf := range intfs {
		if intf.Flags&net.FlagLoopback != 0 {
			continue
		}
		if exclude != nil && exclude[intf.Name] {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(intf.Name), strings.ToLower(keyword)) {
			continue
		}
		label := intf.Name
		if intf.Flags&net.FlagUp == 0 {
			label += "  (down)"
		} else if usedByTunnels != nil && usedByTunnels[intf.Name] {
			label += "  (TH tunnel interface)"
		}
		options = append(options, ui.Option{Label: label, Value: intf.Name})
	}
	sort.Slice(options, func(i, j int) bool { return options[i].Value < options[j].Value })
	return options
}

// collectExternalInterface asks for the bandwidth, link mode and (in
// unicast mode) the explicit neighbour addresses of one external Babel
// interface. Enabling multicast clears any previously entered neighbours.
func collectExternalInterface(p *prompts, name string, existing *config.BabelExternalInterface) (config.BabelExternalInterface, error) {
	external := config.BabelExternalInterface{}
	if existing != nil {
		external = *existing
	}

	bandwidth := strconv.Itoa(external.BandwidthMbps)
	if err := p.input("Bandwidth (Mbps, 0 = unlimited)", &bandwidth, validateNonNegativeIntInput); err != nil {
		return external, err
	}
	external.BandwidthMbps = parseInt(bandwidth)

	multicast, err := p.toggle(fmt.Sprintf("Multicast on %s", name), external.Multicast)
	if err != nil {
		return external, err
	}
	external.Multicast = multicast
	if multicast {
		external.Neighbours = nil
		return external, nil
	}

	neighbours := formatNeighbourList(external.Neighbours)
	if err := p.input("Unicast neighbours (comma separated)", &neighbours, validateNeighbourListInput); err != nil {
		return external, err
	}
	external.Neighbours = parseNeighbourList(neighbours)
	return external, nil
}

func externalInterfaceOptions(interfaces map[string]config.BabelExternalInterface) []ui.Option {
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	options := make([]ui.Option, 0, len(names))
	for _, name := range names {
		mode := "multicast"
		if !interfaces[name].Multicast {
			mode = "unicast"
		}
		options = append(options, ui.Option{Label: name + " (" + mode + ")", Value: name})
	}
	return options
}

func firstExternalInterface(interfaces map[string]config.BabelExternalInterface) string {
	options := externalInterfaceOptions(interfaces)
	if len(options) == 0 {
		return ""
	}
	return options[0].Value
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
	for _, token := range splitNonEmpty(value) {
		addr, err := netip.ParseAddr(token)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() {
			return fmt.Errorf("invalid neighbour address %q", token)
		}
	}
	return nil
}
