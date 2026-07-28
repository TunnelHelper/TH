package app

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func srv6EditOptions(spec *model.SRv6Spec) []ui.Option {
	return []ui.Option{
		{Label: "Route source base URL: " + spec.BaseURL, Value: "base-url"},
		{Label: "Underlay interface: " + spec.UnderlayInterface, Value: "underlay"},
		{Label: fmt.Sprintf("Refresh interval: %d seconds", spec.RefreshIntervalSeconds), Value: "refresh"},
		{Label: fmt.Sprintf("Route sources: %d", len(spec.Sources)), Value: "sources"},
	}
}

func editSRv6Field(prompts *prompts, record *model.Tunnel, field string) error {
	spec := record.Spec.SRv6
	switch field {
	case "base-url":
		return prompts.input("Route source base URL", &spec.BaseURL, validateHTTPURL)
	case "underlay":
		return prompts.input("Underlay interface", &spec.UnderlayInterface, validateInterfaceInput)
	case "refresh":
		return editInt(prompts, "Refresh interval seconds (60-604800)", &spec.RefreshIntervalSeconds, 60, 604800)
	case "sources":
		sources, err := editSRv6Sources(prompts, spec.Sources)
		if err != nil {
			return err
		}
		spec.Sources = sources
	}
	return nil
}

func editSRv6Sources(prompts *prompts, initial []model.SRv6Source) ([]model.SRv6Source, error) {
	sources := append([]model.SRv6Source(nil), initial...)
	for {
		options := make([]ui.Option, 0, len(sources)+2)
		for index, source := range sources {
			options = append(options, ui.Option{Label: source.Name, Value: strconv.Itoa(index)})
		}
		options = append(options, ui.Option{Label: "Add source", Value: "add"}, ui.Option{Label: "Done", Value: "done"})
		choice := "done"
		if err := prompts.selectValue("SRv6 route sources", options, &choice); err != nil {
			return nil, err
		}
		if choice == "done" {
			if len(sources) == 0 {
				prompts.ui.Warn("At least one SRv6 source is required")
				continue
			}
			return sources, nil
		}
		if choice == "add" {
			source, keep, err := collectSRv6Source(prompts, model.SRv6Source{
				Name: suggestedSRv6SourceName(sources), MTU: 1500,
			}, true)
			if err != nil {
				return nil, err
			}
			if keep {
				if err := ensureUniqueSRv6SourceName(prompts, sources, -1, &source.Name); err != nil {
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
			sources[index] = source
		case "remove":
			if len(sources) == 1 {
				prompts.ui.Warn("A tunnel must retain at least one SRv6 source")
			} else {
				sources = append(sources[:index], sources[index+1:]...)
			}
		}
	}
}

func editSRv6Source(prompts *prompts, original model.SRv6Source) (model.SRv6Source, string, error) {
	source := original
	for {
		options := []ui.Option{
			{Label: "Name: " + source.Name, Value: "name"},
			{Label: "IPv4 route SID: " + optionalAddrLabel(source.SIDv4), Value: "sid4"},
			{Label: "IPv6 route SID: " + optionalAddrLabel(source.SIDv6), Value: "sid6"},
			{Label: fmt.Sprintf("MTU: %d", source.MTU), Value: "mtu"},
			{Label: "Save source", Value: "save"},
			{Label: "Remove source", Value: "remove"},
			{Label: "Discard source changes", Value: "discard"},
		}
		choice := "save"
		if err := prompts.selectValue("Source field", options, &choice); err != nil {
			return original, "discard", err
		}
		switch choice {
		case "save":
			if source.SIDv4 == nil && source.SIDv6 == nil {
				prompts.ui.Warn("At least one SID is required")
				continue
			}
			return source, "save", nil
		case "discard":
			return original, "discard", nil
		case "remove":
			confirmed, err := prompts.confirm("Remove this source", false)
			if err != nil {
				return original, "discard", err
			}
			if confirmed {
				return source, "remove", nil
			}
		case "name":
			if err := prompts.input("Source name", &source.Name, validateNameInput); err != nil {
				return original, "discard", err
			}
		case "sid4", "sid6":
			value := optionalAddrInput(source.SIDv4)
			label := "SID for IPv4 routes (blank = none)"
			if field := choice; field == "sid6" {
				value, label = optionalAddrInput(source.SIDv6), "SID for IPv6 routes (blank = none)"
			}
			if err := prompts.input(label, &value, validateOptionalIPv6); err != nil {
				return original, "discard", err
			}
			address, _ := parseOptionalAddr(value)
			if choice == "sid4" {
				source.SIDv4 = address
			} else {
				source.SIDv6 = address
			}
		case "mtu":
			if err := editInt(prompts, "MTU (68-65535)", &source.MTU, 68, 65535); err != nil {
				return original, "discard", err
			}
		}
	}
}

func optionalAddrLabel(value *netip.Addr) string {
	if value == nil {
		return "none"
	}
	return value.String()
}

func optionalAddrInput(value *netip.Addr) string {
	if value == nil {
		return ""
	}
	return value.String()
}
