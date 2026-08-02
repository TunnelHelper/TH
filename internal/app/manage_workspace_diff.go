package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/TunnelHelper/TH/internal/model"
)

type workspaceChange struct {
	Path   string
	Before string
	After  string
}

const workspaceChangeViewportRows = 6

func workspaceTunnelChanges(before, after model.Tunnel) []workspaceChange {
	type editableTunnel struct {
		Name    string     `json:"name"`
		Enabled bool       `json:"enabled"`
		Spec    model.Spec `json:"spec"`
	}
	changes := workspaceStructuredChanges(
		editableTunnel{Name: before.Name, Enabled: before.Enabled, Spec: before.Spec},
		editableTunnel{Name: after.Name, Enabled: after.Enabled, Spec: after.Spec},
	)
	if replacementSecretsRequired(before, after) && !workspaceHasChange(changes, "Key material") && !workspaceHasChange(changes, "Authentication material") {
		label := "Key material"
		if after.Kind == model.KindXFRMIKEv2 {
			label = "Authentication material"
		}
		changes = append(changes, workspaceChange{Path: label, Before: "current", After: "regenerate on save"})
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

func workspacePeerChanges(before, after model.WireGuardPeer, adding bool) []workspaceChange {
	if adding {
		return workspaceStructuredChanges(nil, after)
	}
	return workspaceStructuredChanges(before, after)
}

func workspaceSourceChanges(before, after model.SRv6Source, adding bool) []workspaceChange {
	if adding {
		return workspaceStructuredChanges(nil, after)
	}
	return workspaceStructuredChanges(before, after)
}

func workspaceStructuredChanges(before, after any) []workspaceChange {
	left, leftErr := workspaceJSONValue(before)
	right, rightErr := workspaceJSONValue(after)
	if leftErr != nil || rightErr != nil {
		return nil
	}
	changes := make([]workspaceChange, 0, 8)
	collectWorkspaceChanges("", left, right, &changes)
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

func workspaceJSONValue(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func collectWorkspaceChanges(path string, before, after any, changes *[]workspaceChange) {
	if reflect.DeepEqual(before, after) {
		return
	}
	beforeMap, beforeIsMap := before.(map[string]any)
	afterMap, afterIsMap := after.(map[string]any)
	if beforeIsMap || afterIsMap {
		if beforeIsMap != afterIsMap && len(beforeMap) == 0 && len(afterMap) == 0 {
			*changes = append(*changes, workspaceChange{
				Path: humanWorkspacePath(path), Before: workspaceDiffValue(before), After: workspaceDiffValue(after),
			})
			return
		}
		keys := make(map[string]struct{}, len(beforeMap)+len(afterMap))
		for key := range beforeMap {
			keys[key] = struct{}{}
		}
		for key := range afterMap {
			keys[key] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			collectWorkspaceChanges(workspaceJoinPath(path, key), beforeMap[key], afterMap[key], changes)
		}
		return
	}
	beforeList, beforeIsList := before.([]any)
	afterList, afterIsList := after.([]any)
	if beforeIsList || afterIsList {
		if beforeIsList != afterIsList && len(beforeList) == 0 && len(afterList) == 0 {
			*changes = append(*changes, workspaceChange{
				Path: humanWorkspacePath(path), Before: workspaceDiffValue(before), After: workspaceDiffValue(after),
			})
			return
		}
		length := max(len(beforeList), len(afterList))
		for index := 0; index < length; index++ {
			var left, right any
			if index < len(beforeList) {
				left = beforeList[index]
			}
			if index < len(afterList) {
				right = afterList[index]
			}
			collectWorkspaceChanges(fmt.Sprintf("%s[%d]", path, index+1), left, right, changes)
		}
		return
	}
	label := humanWorkspacePath(path)
	if workspaceSecretPath(path) {
		beforeValue, afterValue := workspaceSecretValues(before, after)
		*changes = append(*changes, workspaceChange{Path: label, Before: beforeValue, After: afterValue})
		return
	}
	*changes = append(*changes, workspaceChange{
		Path: label, Before: workspaceDiffValue(before), After: workspaceDiffValue(after),
	})
}

func workspaceJoinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func workspaceSecretPath(path string) bool {
	lower := strings.ToLower(path)
	for _, token := range []string{
		"private_key", "preshared_key", ".psk", "encryption_key", "authentication_key",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func workspaceSecretValues(before, after any) (string, string) {
	beforeValue := "current"
	afterValue := "replace"
	if text, ok := before.(string); ok && text != "" {
		beforeValue = "staged replacement"
		if text == model.ClearSecretValue {
			beforeValue = "staged removal"
		}
	}
	if after == nil || after == "" {
		afterValue = "keep current"
	}
	if text, ok := after.(string); ok && text == model.ClearSecretValue {
		afterValue = "remove"
	}
	return beforeValue, afterValue
}

func workspaceDiffValue(value any) string {
	switch value := value.(type) {
	case nil:
		return "none"
	case string:
		if value == "" {
			return "none"
		}
		return value
	case bool:
		if value {
			return "enabled"
		}
		return "disabled"
	case json.Number:
		return value.String()
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}
		return string(data)
	}
}

func humanWorkspacePath(path string) string {
	path = strings.TrimPrefix(path, "spec.")
	parts := strings.Split(path, ".")
	if len(parts) > 1 && workspaceSpecSegment(parts[0]) {
		parts = parts[1:]
	}
	for index := range parts {
		parts[index] = humanWorkspaceSegment(parts[index])
	}
	if len(parts) == 0 {
		return "Value"
	}
	return strings.Join(parts, " / ")
}

func workspaceSpecSegment(value string) bool {
	switch value {
	case "gre", "vxlan", "wireguard", "amneziawg", "xfrm_static", "xfrm_ikev2", "srv6":
		return true
	default:
		return false
	}
}

func humanWorkspaceSegment(value string) string {
	indexSuffix := ""
	if bracket := strings.IndexByte(value, '['); bracket >= 0 {
		indexSuffix = " " + value[bracket:]
		value = value[:bracket]
	}
	labels := map[string]string{
		"name": "Name", "addresses": "Interface addresses", "local": "Local underlay", "remote": "Remote underlay",
		"underlay_interface": "Underlay interface", "destination_port": "Destination port", "listen_port": "Listen port",
		"firewall_mark": "Firewall mark", "route_allowed_ips": "AllowedIPs routing", "route_table": "Route table",
		"peers": "Peers", "public_key": "Public key", "preshared_key": "Preshared key", "allowed_ips": "Allowed IPs",
		"keepalive": "Persistent keepalive", "spi_inbound": "Inbound SPI", "spi_outbound": "Outbound SPI",
		"algorithm": "Algorithm", "encryption_key_in": "Inbound encryption key", "encryption_key_out": "Outbound encryption key",
		"authentication_key_in": "Inbound authentication key", "authentication_key_out": "Outbound authentication key",
		"local_address": "Local underlay", "remote_address": "Remote underlay", "local_id": "Local identity", "remote_id": "Remote identity",
		"auth_method": "Authentication", "psk": "Pre-shared key", "local_private_key": "Local private key",
		"local_public_key": "Local public key", "remote_public_key": "Remote public key", "ike_proposal": "IKE proposal",
		"esp_proposal": "ESP proposal", "start_action": "Start action", "family": "Address family",
		"prefix_url": "Prefix file URL", "priority": "Priority", "sid": "Route SID",
		"refresh_interval_seconds": "Refresh interval", "sources": "Route sources",
		"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax", "s1": "S1", "s2": "S2", "h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4",
	}
	if label := labels[value]; label != "" {
		return label + indexSuffix
	}
	value = strings.ReplaceAll(value, "_", " ")
	runes := []rune(value)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes) + indexSuffix
}

func workspaceDiffLines(changes []workspaceChange, width, maxLines int) []string {
	lines := []string{workspaceAccentStyle.Render(fmt.Sprintf("Pending changes  %d", len(changes)))}
	if len(changes) == 0 {
		return append(lines, workspaceDimStyle.Render("No pending changes"))
	}
	for index := range changes {
		change := changes[index]
		line := fmt.Sprintf("%s: %s -> %s", change.Path, change.Before, change.After)
		lines = append(lines, wrapDisplayText(line, max(10, width))...)
	}
	return lines
}

func workspaceDiffWindow(changes []workspaceChange, selected int, focused bool, width, visibleRows int) []string {
	lines := []string{workspaceAccentStyle.Render(fmt.Sprintf("Pending changes  %d", len(changes)))}
	if len(changes) == 0 {
		return append(lines, workspaceDimStyle.Render("No pending changes"))
	}
	selected = max(0, min(selected, len(changes)-1))
	start, end := workspaceVisibleRange(len(changes), selected, max(1, visibleRows))
	if status := workspaceWindowStatus(start, end, len(changes), width); status != "" {
		lines = append(lines, status)
	}
	for index := start; index < end; index++ {
		change := changes[index]
		line := fmt.Sprintf("%s: %s -> %s", change.Path, change.Before, change.After)
		if focused && index == selected {
			line = "> " + line
		} else {
			line = "  " + line
		}
		line = fit(line, max(10, width))
		if focused && index == selected {
			line = workspaceFocusStyle.Render(line)
		}
		lines = append(lines, line)
	}
	return lines
}

func workspaceChangeDetailLines(change workspaceChange) []string {
	return []string{
		"Field:  " + change.Path,
		"",
		"Before: " + change.Before,
		"",
		"After:  " + change.After,
	}
}

func workspaceHasChange(changes []workspaceChange, path string) bool {
	for _, change := range changes {
		if strings.Contains(change.Path, path) {
			return true
		}
	}
	return false
}
