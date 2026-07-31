package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type prompts struct {
	ui       *ui.UI
	prompter *ui.Prompter
}

const maxInterfaceNameLength = 15

func newPrompts(output *ui.UI) *prompts {
	return &prompts{ui: output, prompter: ui.NewPrompter(output)}
}

func (p *prompts) section(title, description string) {
	p.ui.Title(title)
	p.ui.Dim(description)
}

func (p *prompts) selectValue(title string, options []ui.Option, value *string) error {
	for {
		err := p.prompter.Select(title, options, value)
		if err == nil {
			return nil
		}
		if wrapped := wrapAbort(err); errors.Is(wrapped, ErrAborted) {
			return wrapped
		}
		p.ui.Warn(err.Error())
	}
}

func (p *prompts) input(title string, value *string, validate func(string) error) error {
	return p.inputWithPrefix(title, "", value, validate)
}

func (p *prompts) inputWithPrefix(title, prefix string, value *string, validate func(string) error) error {
	for {
		var err error
		if prefix == "" {
			err = p.prompter.Input(title, value, validate)
		} else {
			err = p.prompter.InputWithPrefixLimit(title, prefix, maxInterfaceNameLength, value, validate)
		}
		if err == nil {
			*value = strings.TrimSpace(*value)
			return nil
		}
		if wrapped := wrapAbort(err); errors.Is(wrapped, ErrAborted) {
			return wrapped
		}
		p.ui.Warn(err.Error())
	}
}

func (p *prompts) secret(title string, value *string, validate func(string) error) error {
	for {
		err := p.prompter.Secret(title, value, validate)
		if err == nil {
			*value = strings.TrimSpace(*value)
			return nil
		}
		if wrapped := wrapAbort(err); errors.Is(wrapped, ErrAborted) {
			return wrapped
		}
		p.ui.Warn(err.Error())
	}
}

func (p *prompts) decision(title string, primary, secondary ui.Option, defaultValue string) (string, error) {
	value := defaultValue
	for {
		err := p.prompter.Decision(title, primary, secondary, &value)
		if err == nil {
			return value, nil
		}
		if wrapped := wrapAbort(err); errors.Is(wrapped, ErrAborted) {
			return "", wrapped
		}
		p.ui.Warn(err.Error())
	}
}

func (p *prompts) saveDiscard(title, saveLabel, discardLabel string) (bool, error) {
	value, err := p.decision(title,
		ui.Option{Label: saveLabel, Value: "save"},
		ui.Option{Label: discardLabel, Value: "discard", Destructive: true},
		"save",
	)
	return value == "save", err
}

func (p *prompts) confirmAction(title, actionLabel string) (bool, error) {
	value, err := p.decision(title,
		ui.Option{Label: actionLabel, Value: "confirm", Destructive: true},
		ui.Option{Label: "Cancel", Value: "cancel"},
		"cancel",
	)
	return value == "confirm", err
}

func (p *prompts) toggle(title string, enabled bool) (bool, error) {
	defaultValue := "disabled"
	if enabled {
		defaultValue = "enabled"
	}
	value, err := p.decision(title,
		ui.Option{Label: "Enabled", Value: "enabled"},
		ui.Option{Label: "Disabled", Value: "disabled"},
		defaultValue,
	)
	return value == "enabled", err
}

func required(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value is required")
	}
	return nil
}

func validateInterfaceInput(value string) error {
	if len(value) == 0 || len(value) > 15 {
		return errors.New("interface name must contain 1-15 characters")
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return errors.New("interface name contains unsupported characters")
		}
	}
	return nil
}

func validateInterfaceNameLength(prefix, name string) error {
	total := len(prefix) + len(name)
	if total > maxInterfaceNameLength {
		return fmt.Errorf("interface name must contain at most %d characters (prefix + name: %d)", maxInterfaceNameLength, total)
	}
	return nil
}

func validateNameInput(value string) error {
	if len(value) == 0 || len(value) > 64 {
		return errors.New("name must contain 1-64 characters")
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return errors.New("name contains unsupported characters")
		}
	}
	return nil
}

func validateAddrInput(value string) error {
	_, err := netip.ParseAddr(strings.TrimSpace(value))
	return err
}

func validateIKEAddrInput(value string) error {
	value = strings.TrimSpace(value)
	if value == "%any" || value == "%any4" || value == "%any6" {
		return nil
	}
	return validateAddrInput(value)
}

func validateInterfacePrefixesInput(value string) error {
	return validatePrefixList(value, model.MaxInterfaceAddresses, false)
}

func validateAllowedPrefixesInput(value string) error {
	return validatePrefixList(value, model.MaxAllowedIPsPerPeer, true)
}

func validatePrefixList(value string, maximum int, masked bool) error {
	prefixes, err := parsePrefixes(value)
	if err != nil {
		return err
	}
	if len(prefixes) > maximum {
		return fmt.Errorf("must contain at most %d prefixes", maximum)
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if masked {
			prefix = prefix.Masked()
		}
		if _, exists := seen[prefix]; exists {
			return fmt.Errorf("duplicate prefix %s", prefix)
		}
		seen[prefix] = struct{}{}
	}
	return nil
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func formatPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	return strings.Join(values, ",")
}

func validateInt(minimum, maximum int) func(string) error {
	return func(value string) error {
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || number < minimum || number > maximum {
			return fmt.Errorf("must be between %d and %d", minimum, maximum)
		}
		return nil
	}
}

func parseInt(value string) int {
	number, _ := strconv.Atoi(strings.TrimSpace(value))
	return number
}

func validateWireGuardKey(value string) error {
	_, err := wgtypes.ParseKey(strings.TrimSpace(value))
	return err
}

func validateOptionalWireGuardKey(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return validateWireGuardKey(value)
}

func validateEndpointInput(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("endpoint must use host:port syntax")
	}
	return validateInt(1, 65535)(port)
}
