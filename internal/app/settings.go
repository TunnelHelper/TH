package app

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/ui"
)

// editBabelSettings edits the daemon-global Babel settings through the
// local API and persists them.
func (a *tuiApp) editBabelSettings() error {
	ctx, cancel := a.context()
	settings, err := a.client.Settings(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("load Babel settings: %w", err)
	}

	if err := a.prompts.input("Router ID (16 hex chars, empty = generated)", &settings.RouterID, validateBabelRouterIDInput); err != nil {
		return err
	}
	delayMetric := "Enabled"
	if !settings.DelayMetricEnabled() {
		delayMetric = "Disabled"
	}
	if err := a.prompts.selectValue("Delay-based cost (RFC 9616)", []ui.Option{
		{Label: "Enabled", Value: "Enabled"},
		{Label: "Disabled", Value: "Disabled"},
	}, &delayMetric); err != nil {
		return err
	}
	settings.DelayMetric = boolPtr(delayMetric == "Enabled")

	// ECMP balance knob: bias in [-2, 2] maps to the weight exponents
	// (alpha = 1 + bias, beta = 1 - bias, clamped to [0, 4]). Moving left
	// favours low latency, moving right favours bandwidth; the centre is
	// the default (1, 1).
	bias := balanceBias(settings.WeightBandwidthExponent, settings.WeightRTTExponent)
	if err := a.prompts.slider("ECMP balance (right = bandwidth, left = latency)", -2, 2, 1, &bias, renderBalanceSlider); err != nil {
		return err
	}
	settings.WeightBandwidthExponent = clampExponent(1 + bias)
	settings.WeightRTTExponent = clampExponent(1 - bias)

	routeTable := strconv.Itoa(settings.RouteTable)
	if err := a.prompts.input("Route table (0 = main)", &routeTable, validateNonNegativeIntInput); err != nil {
		return err
	}
	settings.RouteTable, _ = strconv.Atoi(routeTable)

	helloSeconds := strconv.Itoa(settings.UnicastHelloSeconds)
	if err := a.prompts.input("Unicast Hello seconds (0 = default 4)", &helloSeconds, validateNonNegativeIntInput); err != nil {
		return err
	}
	settings.UnicastHelloSeconds, _ = strconv.Atoi(helloSeconds)

	maxPaths := strconv.Itoa(settings.MultipathMaxPaths)
	if err := a.prompts.input("Max ECMP paths (0 = default 4)", &maxPaths, validateNonNegativeIntInput); err != nil {
		return err
	}
	settings.MultipathMaxPaths, _ = strconv.Atoi(maxPaths)

	slack := strconv.Itoa(settings.MultipathSlack)
	if err := a.prompts.input("Multipath cost slack (0 = equal cost only)", &slack, validateNonNegativeIntInput); err != nil {
		return err
	}
	settings.MultipathSlack, _ = strconv.Atoi(slack)

	sources := strings.Join(settings.Advertise.SourceInterfaces, ",")
	if err := a.prompts.input("Advertise source interfaces (comma separated)", &sources, validateInterfaceListInput); err != nil {
		return err
	}
	settings.Advertise.SourceInterfaces = splitNonEmpty(sources)

	explicit := formatPrefixList(settings.Advertise.AdvertisedPrefixes)
	if err := a.prompts.input("Explicit advertised prefixes (empty = discover)", &explicit, validatePrefixListInput); err != nil {
		return err
	}
	settings.Advertise.AdvertisedPrefixes = parsePrefixList(explicit)

	include := formatPrefixList(settings.Advertise.Include)
	if err := a.prompts.input("Include filter (empty = allow all)", &include, validatePrefixListInput); err != nil {
		return err
	}
	settings.Advertise.Include = parsePrefixList(include)

	exclude := formatPrefixList(settings.Advertise.Exclude)
	if err := a.prompts.input("Exclude filter", &exclude, validatePrefixListInput); err != nil {
		return err
	}
	settings.Advertise.Exclude = parsePrefixList(exclude)

	if err := settings.Validate(); err != nil {
		return fmt.Errorf("invalid Babel settings: %w", err)
	}
	proceed, err := a.prompts.confirmAction("Save Babel settings?", "Save")
	if err != nil || !proceed {
		return err
	}

	ctx, cancel = a.context()
	defer cancel()
	if err := a.client.UpdateSettings(ctx, settings); err != nil {
		return fmt.Errorf("update Babel settings: %w", err)
	}
	a.ui.Info("Babel settings saved")
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

// renderBalanceSlider draws the bandwidth/latency balance knob.
func renderBalanceSlider(value float64) string {
	const positions = 21
	index := int(math.Round((value + 2) / 4 * float64(positions-1)))
	bar := strings.Repeat("─", index) + "●" + strings.Repeat("─", positions-1-index)
	alpha := math.Max(0, 1+value)
	beta := math.Max(0, 1-value)
	return fmt.Sprintf("延迟 ◄ %s ► 带宽    α=%.1f β=%.1f", bar, alpha, beta)
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
