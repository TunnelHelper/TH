package app

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func srv6EditOptions(spec *model.SRv6Spec) []ui.Option {
	return []ui.Option{
		{Label: "Underlay interface: " + spec.UnderlayInterface, Value: "underlay"},
		{Label: fmt.Sprintf("Refresh interval: %d seconds", spec.RefreshIntervalSeconds), Value: "refresh"},
		{Label: fmt.Sprintf("Route sources: %d", len(spec.Sources)), Value: "sources"},
	}
}

func editSRv6Field(prompts *prompts, record *model.Tunnel, field string) error {
	spec := record.Spec.SRv6
	switch field {
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
			options = append(options, ui.Option{Label: srv6SourceOptionLabel(source), Value: strconv.Itoa(index)})
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
			})
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
			{Label: "Prefix file URL: " + source.PrefixURL, Value: "url"},
			{Label: fmt.Sprintf("Priority: %d", source.Priority), Value: "priority"},
			{Label: "Route SID: " + srv6SIDInput(source.SID), Value: "sid"},
			{Label: fmt.Sprintf("MTU: %d", source.MTU), Value: "mtu"},
			{Label: "Finish editing", Value: "finish"},
			{Label: "Remove source", Value: "remove"},
		}
		choice := "finish"
		if err := prompts.selectValue(srv6FamilyDisplay(source.Family)+" source field", options, &choice); err != nil {
			return original, "discard", err
		}
		switch choice {
		case "finish":
			if err := validateSRv6SourceFields(source); err != nil {
				prompts.ui.Warn(err.Error())
				continue
			}
			save, err := prompts.saveDiscard("Source changes", "Save source", "Discard changes")
			if err != nil {
				return original, "discard", err
			}
			if save {
				return source, "save", nil
			}
			return original, "discard", nil
		case "remove":
			confirmed, err := prompts.confirmAction("Remove this source", "Remove source")
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
		case "url":
			if err := prompts.input(srv6FamilyDisplay(source.Family)+" prefix file URL", &source.PrefixURL, validateHTTPURL); err != nil {
				return original, "discard", err
			}
			source.PrefixURL = strings.TrimSpace(source.PrefixURL)
		case "priority":
			if err := editInt(prompts, "Priority (0-2147483647, higher wins)", &source.Priority, 0, 2147483647); err != nil {
				return original, "discard", err
			}
		case "sid":
			value := srv6SIDInput(source.SID)
			if err := prompts.input("Route SID", &value, validateRequiredIPv6); err != nil {
				return original, "discard", err
			}
			source.SID, _ = netip.ParseAddr(strings.TrimSpace(value))
		case "mtu":
			if err := editInt(prompts, "MTU (68-65535)", &source.MTU, 68, 65535); err != nil {
				return original, "discard", err
			}
		}
	}
}
