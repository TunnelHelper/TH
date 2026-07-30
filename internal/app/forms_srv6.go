package app

import (
	"fmt"
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
			BaseURL:                "https://cira.moedove.com",
			UnderlayInterface:      underlay.Interface,
			Table:                  100,
			RefreshIntervalSeconds: 3600,
		}
		record.Spec = model.Spec{SRv6: spec}
	}
	table := strconv.Itoa(spec.Table)
	refresh := strconv.Itoa(spec.RefreshIntervalSeconds)
	if err := prompts.input("Route source base URL", &spec.BaseURL, validateHTTPURL); err != nil {
		return err
	}
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
			options = append(options, ui.Option{Label: source.Name, Value: strconv.Itoa(i)})
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
	for _, candidate := range []string{"chinamobile", "chinaunicom", "chinatelecom", "cernet_edu"} {
		if !used[candidate] {
			return candidate
		}
	}
	if !used["carrier"] {
		return "carrier"
	}
	for suffix := 2; ; suffix++ {
		candidate := "carrier" + strconv.Itoa(suffix)
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

func collectSRv6Source(prompts *prompts, source model.SRv6Source) (model.SRv6Source, bool, error) {
	if source.Name == "" {
		source.Name = "carrier"
	}
	sidV4, sidV6 := "", ""
	if source.SIDv4 != nil {
		sidV4 = source.SIDv4.String()
	}
	if source.SIDv6 != nil {
		sidV6 = source.SIDv6.String()
	}
	mtu := strconv.Itoa(source.MTU)
	if err := prompts.input("Source name", &source.Name, validateNameInput); err != nil {
		return source, false, err
	}
	for {
		if err := prompts.input("SID for IPv4 routes (blank = none)", &sidV4, validateOptionalIPv6); err != nil {
			return source, false, err
		}
		if err := prompts.input("SID for IPv6 routes (blank = none)", &sidV6, validateOptionalIPv6); err != nil {
			return source, false, err
		}
		if sidV4 != "" || sidV6 != "" {
			break
		}
		prompts.ui.Warn("At least one SID is required")
	}
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
		return source, false, err
	}
	source.SIDv4, _ = parseOptionalAddr(sidV4)
	source.SIDv6, _ = parseOptionalAddr(sidV6)
	source.MTU = parseInt(mtu)
	save, err := prompts.saveDiscard("Source", "Add source", "Discard source")
	if err != nil {
		return source, false, err
	}
	return source, save, nil
}

func validateHTTPURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("must be an absolute HTTP or HTTPS URL")
	}
	return nil
}
