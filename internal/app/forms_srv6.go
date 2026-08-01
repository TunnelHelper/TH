package app

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func collectSRv6(prompts *prompts, record *model.Tunnel, creating bool) error {
	spec := record.Spec.SRv6
	if spec == nil {
		underlay := defaultUnderlayDefaults()
		spec = &model.SRv6Spec{
			UnderlayInterface:      underlay.Interface,
			Table:                  100,
			RefreshIntervalSeconds: 3600,
		}
		record.Spec = model.Spec{SRv6: spec}
	}
	table := strconv.Itoa(spec.Table)
	refresh := strconv.Itoa(spec.RefreshIntervalSeconds)
	if err := prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput); err != nil {
		return err
	}
	if creating {
		if err := prompts.input("Route table", &table, validateInt(1, 2147483647)); err != nil {
			return err
		}
	}
	if err := prompts.input("Refresh interval seconds", &refresh, validateInt(60, 604800)); err != nil {
		return err
	}
	sources, err := collectSRv6Sources(prompts, spec.Sources)
	if err != nil {
		return err
	}
	spec.Table = parseInt(table)
	spec.RefreshIntervalSeconds = parseInt(refresh)
	spec.Sources = sources
	return nil
}

func collectSRv6Sources(prompts *prompts, initial []model.SRv6Source) ([]model.SRv6Source, error) {
	sources := append([]model.SRv6Source(nil), initial...)
	for {
		options := make([]ui.Option, 0, len(sources)+2)
		for i, source := range sources {
			options = append(options, ui.Option{Label: srv6SourceOptionLabel(source), Value: strconv.Itoa(i)})
		}
		options = append(options, ui.Option{Label: "Add source", Value: "add"})
		if len(sources) > 0 {
			options = append(options, ui.Option{Label: "Done", Value: "done"})
		}
		choice := "done"
		if len(sources) == 0 {
			choice = "add"
		}
		if err := prompts.selectValue("SRv6 route sources", options, &choice); err != nil {
			return nil, err
		}
		if choice == "done" {
			return sources, nil
		}
		if choice == "add" {
			source, keep, err := collectSRv6Source(prompts, model.SRv6Source{
				Name: suggestedSRv6SourceName(sources), Priority: model.NextSRv6SourcePriority(sources), MTU: 1500,
			})
			if err != nil {
				return nil, err
			}
			if keep {
				if err := ensureUniqueSRv6SourceName(prompts, sources, -1, &source.Name); err != nil {
					return nil, err
				}
				if err := ensureUniqueSRv6SourcePriority(prompts, sources, -1, &source.Priority); err != nil {
					return nil, err
				}
				sources = append(sources, source)
			}
			continue
		}
		index, _ := strconv.Atoi(choice)
		if index < 0 || index >= len(sources) {
			continue
		}
		source, action, err := editSRv6Source(prompts, sources[index])
		if err != nil {
			return nil, err
		}
		switch action {
		case "save":
			if err := ensureUniqueSRv6SourceName(prompts, sources, index, &source.Name); err != nil {
				return nil, err
			}
			if err := ensureUniqueSRv6SourcePriority(prompts, sources, index, &source.Priority); err != nil {
				return nil, err
			}
			sources[index] = source
		case "remove":
			if len(sources) == 1 {
				prompts.ui.Warn("A tunnel must retain at least one SRv6 source")
				continue
			}
			sources = append(sources[:index], sources[index+1:]...)
		}
	}
}

func suggestedSRv6SourceName(sources []model.SRv6Source) string {
	used := make(map[string]bool, len(sources))
	for _, source := range sources {
		used[source.Name] = true
	}
	for suffix := 1; ; suffix++ {
		candidate := "source" + strconv.Itoa(suffix)
		if !used[candidate] {
			return candidate
		}
	}
}

func ensureUniqueSRv6SourceName(prompts *prompts, sources []model.SRv6Source, except int, name *string) error {
	validator := func(value string) error {
		if err := validateNameInput(value); err != nil {
			return err
		}
		for index, source := range sources {
			if index != except && source.Name == value {
				return fmt.Errorf("source name %q is already in use", value)
			}
		}
		return nil
	}
	if err := validator(*name); err == nil {
		return nil
	} else {
		prompts.ui.Warn(err.Error())
	}
	return prompts.input("Source name", name, validator)
}

func ensureUniqueSRv6SourcePriority(prompts *prompts, sources []model.SRv6Source, except int, priority *int) error {
	validator := func(value string) error {
		if err := validateInt(model.SRv6RulePriorityMin, model.SRv6RulePriorityMax)(value); err != nil {
			return err
		}
		candidate := parseInt(value)
		for index, source := range sources {
			if index != except && source.Priority == candidate {
				return fmt.Errorf("source priority %d is already in use", candidate)
			}
		}
		return nil
	}
	value := strconv.Itoa(*priority)
	if err := validator(value); err == nil {
		return nil
	} else {
		prompts.ui.Warn(err.Error())
	}
	if err := prompts.input("Priority (1-32765, lower wins)", &value, validator); err != nil {
		return err
	}
	*priority = parseInt(value)
	return nil
}

func collectSRv6Source(prompts *prompts, source model.SRv6Source) (model.SRv6Source, bool, error) {
	creating := source.Family == ""
	if creating {
		family := string(model.SRv6FamilyIPv4)
		if err := prompts.selectValue("Address family", []ui.Option{
			{Label: "IPv4 prefixes", Value: string(model.SRv6FamilyIPv4)},
			{Label: "IPv6 prefixes", Value: string(model.SRv6FamilyIPv6)},
		}, &family); err != nil {
			return source, false, err
		}
		source.Family = model.SRv6AddressFamily(family)
		if source.Priority == 0 {
			source.Priority = 100
		}
	}
	if source.Name == "" {
		source.Name = "source1"
	}
	if source.MTU == 0 {
		source.MTU = 1500
	}
	if err := prompts.input("Source name", &source.Name, validateNameInput); err != nil {
		return source, false, err
	}
	if err := prompts.input(srv6FamilyDisplay(source.Family)+" prefix file URL", &source.PrefixURL, validateHTTPURL); err != nil {
		return source, false, err
	}
	source.PrefixURL = strings.TrimSpace(source.PrefixURL)
	priority := strconv.Itoa(source.Priority)
	if err := prompts.input("Priority (lower wins)", &priority, validateInt(model.SRv6RulePriorityMin, model.SRv6RulePriorityMax)); err != nil {
		return source, false, err
	}
	sid := srv6SIDInput(source.SID)
	if err := prompts.input("Route SID", &sid, validateRequiredIPv6); err != nil {
		return source, false, err
	}
	mtu := strconv.Itoa(source.MTU)
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
		return source, false, err
	}
	source.SID, _ = netip.ParseAddr(strings.TrimSpace(sid))
	source.Priority = parseInt(priority)
	source.MTU = parseInt(mtu)
	save, err := prompts.saveDiscard("Source", "Add source", "Discard source")
	if err != nil {
		return source, false, err
	}
	return source, save, nil
}

func validateSRv6SourceFields(source model.SRv6Source) error {
	switch source.Family {
	case model.SRv6FamilyIPv4, model.SRv6FamilyIPv6:
	default:
		return fmt.Errorf("address family must be IPv4 or IPv6")
	}
	if err := validateHTTPURL(source.PrefixURL); err != nil {
		return fmt.Errorf("prefix file URL: %w", err)
	}
	if !source.SID.IsValid() || !source.SID.Is6() || source.SID.IsUnspecified() {
		return fmt.Errorf("SID must be a specified IPv6 address")
	}
	if source.Priority < model.SRv6RulePriorityMin || source.Priority > model.SRv6RulePriorityMax {
		return fmt.Errorf("priority must be between %d and %d", model.SRv6RulePriorityMin, model.SRv6RulePriorityMax)
	}
	return nil
}

func srv6FamilyDisplay(family model.SRv6AddressFamily) string {
	if family == model.SRv6FamilyIPv6 {
		return "IPv6"
	}
	return "IPv4"
}

func srv6SIDInput(sid netip.Addr) string {
	if !sid.IsValid() {
		return ""
	}
	return sid.String()
}

func srv6SourceOptionLabel(source model.SRv6Source) string {
	return fmt.Sprintf("%s [%s] priority %d", source.Name, srv6FamilyDisplay(source.Family), source.Priority)
}

func validateRequiredIPv6(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("a specified IPv6 address is required")
	}
	return validateOptionalIPv6(value)
}

func validateHTTPURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("must be an absolute HTTP or HTTPS URL")
	}
	return nil
}
