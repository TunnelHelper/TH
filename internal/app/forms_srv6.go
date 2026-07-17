package app

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/sudogeeker/tunnel-helper/internal/ui"
)

func collectSRv6(prompts *prompts, record *model.Tunnel, creating bool) error {
	spec := record.Spec.SRv6
	if spec == nil {
		spec = &model.SRv6Spec{
			BaseURL:                "https://example.invalid/routes/",
			UnderlayInterface:      "eth0",
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
	if len(sources) == 0 {
		return errors.New("at least one SRv6 source is required")
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
		options = append(options, ui.Option{Label: "Add source", Value: "add"}, ui.Option{Label: "Done", Value: "done"})
		choice := "done"
		if err := prompts.selectValue("SRv6 route sources", options, &choice); err != nil {
			return nil, err
		}
		if choice == "done" {
			return sources, nil
		}
		if choice == "add" {
			source, keep, err := collectSRv6Source(prompts, model.SRv6Source{MTU: 1500}, true)
			if err != nil {
				return nil, err
			}
			if keep {
				sources = append(sources, source)
			}
			continue
		}
		index, _ := strconv.Atoi(choice)
		if index < 0 || index >= len(sources) {
			continue
		}
		source, keep, err := collectSRv6Source(prompts, sources[index], false)
		if err != nil {
			return nil, err
		}
		if keep {
			sources[index] = source
		} else {
			sources = append(sources[:index], sources[index+1:]...)
		}
	}
}

func collectSRv6Source(prompts *prompts, source model.SRv6Source, adding bool) (model.SRv6Source, bool, error) {
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
	if err := prompts.input("SID for IPv4 routes", &sidV4, validateOptionalIPv6); err != nil {
		return source, false, err
	}
	if err := prompts.input("SID for IPv6 routes", &sidV6, validateOptionalIPv6); err != nil {
		return source, false, err
	}
	if sidV4 == "" && sidV6 == "" {
		return source, false, errors.New("at least one SID is required")
	}
	if err := prompts.input("MTU", &mtu, validateInt(68, 65535)); err != nil {
		return source, false, err
	}
	source.SIDv4, _ = parseOptionalAddr(sidV4)
	source.SIDv6, _ = parseOptionalAddr(sidV6)
	source.MTU = parseInt(mtu)
	if !adding {
		remove, err := prompts.confirm("Remove this source", false)
		if err != nil {
			return source, false, err
		}
		if remove {
			return source, false, nil
		}
	}
	return source, true, nil
}

func validateHTTPURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("must be an absolute HTTP or HTTPS URL")
	}
	return nil
}
