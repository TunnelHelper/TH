package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
)

const (
	legacySchemaVersion   = 2
	previousSchemaVersion = 3
)

type SchemaMigration struct {
	RecordID     string
	From         int
	To           int
	PreviousName string
	Name         string
}

type schema2Tunnel struct {
	SchemaVersion int         `json:"schema_version"`
	ID            string      `json:"id"`
	Generation    uint64      `json:"generation"`
	Name          string      `json:"name"`
	Kind          model.Kind  `json:"kind"`
	Interface     string      `json:"interface,omitempty"`
	Enabled       bool        `json:"enabled"`
	Spec          schema2Spec `json:"spec"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

type schema2Spec struct {
	GRE        *model.GRESpec        `json:"gre,omitempty"`
	VXLAN      *model.VXLANSpec      `json:"vxlan,omitempty"`
	WireGuard  *model.WireGuardSpec  `json:"wireguard,omitempty"`
	AmneziaWG  *model.AmneziaWGSpec  `json:"amneziawg,omitempty"`
	XFRMStatic *model.XFRMStaticSpec `json:"xfrm_static,omitempty"`
	XFRMIKEv2  *model.XFRMIKEv2Spec  `json:"xfrm_ikev2,omitempty"`
	SRv6       *schema2SRv6Spec      `json:"srv6,omitempty"`
}

type schema2SRv6Spec struct {
	BaseURL                string              `json:"base_url"`
	UnderlayInterface      string              `json:"underlay_interface"`
	Table                  int                 `json:"table"`
	RefreshIntervalSeconds int                 `json:"refresh_interval_seconds"`
	Sources                []schema2SRv6Source `json:"sources"`
}

type schema2SRv6Source struct {
	Name  string      `json:"name"`
	SIDv4 *netip.Addr `json:"sid_v4,omitempty"`
	SIDv6 *netip.Addr `json:"sid_v6,omitempty"`
	MTU   int         `json:"mtu"`
}

type schema3Tunnel struct {
	SchemaVersion int         `json:"schema_version"`
	ID            string      `json:"id"`
	Generation    uint64      `json:"generation"`
	Name          string      `json:"name"`
	Kind          model.Kind  `json:"kind"`
	Interface     string      `json:"interface,omitempty"`
	Enabled       bool        `json:"enabled"`
	Spec          schema3Spec `json:"spec"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

type schema3Spec struct {
	GRE        *model.GRESpec        `json:"gre,omitempty"`
	VXLAN      *model.VXLANSpec      `json:"vxlan,omitempty"`
	WireGuard  *model.WireGuardSpec  `json:"wireguard,omitempty"`
	AmneziaWG  *model.AmneziaWGSpec  `json:"amneziawg,omitempty"`
	XFRMStatic *model.XFRMStaticSpec `json:"xfrm_static,omitempty"`
	XFRMIKEv2  *model.XFRMIKEv2Spec  `json:"xfrm_ikev2,omitempty"`
	SRv6       *schema3SRv6Spec      `json:"srv6,omitempty"`
}

type schema3SRv6Spec struct {
	UnderlayInterface      string             `json:"underlay_interface"`
	Table                  int                `json:"table"`
	RefreshIntervalSeconds int                `json:"refresh_interval_seconds"`
	Sources                []model.SRv6Source `json:"sources"`
}

type recordMigrationPlan struct {
	id           string
	record       model.Tunnel
	from         int
	previousName string
}

type decodedMigrationRecord struct {
	id           string
	version      int
	record       model.Tunnel
	rewrite      bool
	previousName string
}

func (s *FileStore) migrateRecords() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read tunnel store for migration: %w", err)
	}
	decoded := make([]decodedMigrationRecord, 0)
	recordCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		recordCount++
		if recordCount > model.MaxTunnelRecords {
			return fmt.Errorf("tunnel store exceeds %d records", model.MaxTunnelRecords)
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !model.ValidID(id) {
			return fmt.Errorf("invalid record filename %q", entry.Name())
		}
		data, err := s.readRecordDataLocked(id)
		if err != nil {
			return err
		}
		version, err := schemaVersion(data)
		if err != nil {
			return fmt.Errorf("decode tunnel record %s: %w", id, err)
		}
		var record model.Tunnel
		needsRewrite := version != model.SchemaVersion
		if version == legacySchemaVersion {
			record, err = migrateSchema2(data)
			if err != nil {
				return fmt.Errorf("migrate tunnel record %s from schema %d to %d: %w", id, version, model.SchemaVersion, err)
			}
		} else if version == previousSchemaVersion {
			record, err = migrateSchema3(data)
			if err != nil {
				return fmt.Errorf("migrate tunnel record %s from schema %d to %d: %w", id, version, model.SchemaVersion, err)
			}
		} else {
			record, err = decodeCurrentRecord(data)
			if err != nil {
				return fmt.Errorf("validate tunnel record %s: %w", id, err)
			}
		}
		if record.ID != id {
			return fmt.Errorf("record %s contains mismatched id %q", id, record.ID)
		}
		previousName := ""
		prefixedName := model.PrefixedTunnelName(record.Kind, record.Name)
		if prefixedName != record.Name {
			previousName = record.Name
			record.Name = prefixedName
			needsRewrite = true
		}
		decoded = append(decoded, decodedMigrationRecord{
			id: id, version: version, record: record, rewrite: needsRewrite, previousName: previousName,
		})
	}

	usedPriorities := make(map[int]struct{})
	for _, item := range decoded {
		if item.version != model.SchemaVersion || item.record.Kind != model.KindSRv6 || item.record.Spec.SRv6 == nil {
			continue
		}
		priority := item.record.Spec.SRv6.RulePriority
		if _, exists := usedPriorities[priority]; exists {
			return fmt.Errorf("policy-rule priority %d is shared after migration", priority)
		}
		usedPriorities[priority] = struct{}{}
	}
	plans := make([]recordMigrationPlan, 0)
	names := make(map[string]string)
	for index := range decoded {
		item := &decoded[index]
		if item.record.Kind == model.KindSRv6 && item.record.Spec.SRv6 != nil && item.record.Spec.SRv6.RulePriority == 0 {
			priority, err := model.AllocateSRv6RulePriority(usedPriorities)
			if err != nil {
				return fmt.Errorf("allocate SRv6 policy-rule priority for record %s: %w", item.id, err)
			}
			item.record.Spec.SRv6.RulePriority = priority
			usedPriorities[priority] = struct{}{}
			item.rewrite = true
		}
		if err := model.Validate(&item.record); err != nil {
			return fmt.Errorf("validate tunnel record %s after migration: %w", item.id, err)
		}
		if owner, exists := names[item.record.Name]; exists {
			return fmt.Errorf("tunnel name %q is shared by records %s and %s after migration", item.record.Name, owner, item.id)
		}
		names[item.record.Name] = item.id
		if item.rewrite {
			plans = append(plans, recordMigrationPlan{
				id: item.id, record: item.record, from: item.version, previousName: item.previousName,
			})
		}
	}

	for _, plan := range plans {
		if err := s.replaceRecordLocked(plan.record); err != nil {
			return fmt.Errorf("commit migration for tunnel record %s: %w", plan.id, err)
		}
		if err := s.syncDirectory(s.dir); err != nil {
			return fmt.Errorf("sync migration for tunnel record %s: %w", plan.id, err)
		}
		s.migrations = append(s.migrations, SchemaMigration{
			RecordID: plan.id, From: plan.from, To: model.SchemaVersion,
			PreviousName: plan.previousName, Name: plan.record.Name,
		})
	}
	return nil
}

func (s *FileStore) readRecordDataLocked(id string) ([]byte, error) {
	info, err := os.Lstat(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("inspect tunnel record %s: %w", id, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("tunnel record %s is not a regular file", id)
	}
	if err := requireProcessOwnership(info); err != nil {
		return nil, fmt.Errorf("tunnel record %s: %w", id, err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("tunnel record %s has unsafe mode %04o", id, info.Mode().Perm())
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("tunnel record %s exceeds 4 MiB", id)
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, fmt.Errorf("read tunnel record %s: %w", id, err)
	}
	return data, nil
}

func schemaVersion(data []byte) (int, error) {
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := decodeSingleJSON(data, &header, false); err != nil {
		return 0, err
	}
	return header.SchemaVersion, nil
}

func decodeCurrentRecord(data []byte) (model.Tunnel, error) {
	var record model.Tunnel
	if err := decodeSingleJSON(data, &record, true); err != nil {
		return model.Tunnel{}, err
	}
	if err := model.Validate(&record); err != nil {
		return model.Tunnel{}, err
	}
	return record, nil
}

func migrateSchema2(data []byte) (model.Tunnel, error) {
	var legacy schema2Tunnel
	if err := decodeSingleJSON(data, &legacy, true); err != nil {
		return model.Tunnel{}, err
	}
	if legacy.SchemaVersion != legacySchemaVersion {
		return model.Tunnel{}, fmt.Errorf("expected schema_version %d, got %d", legacySchemaVersion, legacy.SchemaVersion)
	}
	record := model.Tunnel{
		SchemaVersion: model.SchemaVersion,
		ID:            legacy.ID,
		Generation:    legacy.Generation,
		Name:          model.PrefixedTunnelName(legacy.Kind, legacy.Name),
		Kind:          legacy.Kind,
		Interface:     legacy.Interface,
		Enabled:       legacy.Enabled,
		Spec: model.Spec{
			GRE: legacy.Spec.GRE, VXLAN: legacy.Spec.VXLAN,
			WireGuard: legacy.Spec.WireGuard, AmneziaWG: legacy.Spec.AmneziaWG,
			XFRMStatic: legacy.Spec.XFRMStatic, XFRMIKEv2: legacy.Spec.XFRMIKEv2,
		},
		CreatedAt: legacy.CreatedAt,
		UpdatedAt: legacy.UpdatedAt,
	}
	if legacy.Spec.SRv6 != nil {
		migrated, err := migrateSchema2SRv6(legacy.Spec.SRv6)
		if err != nil {
			return model.Tunnel{}, err
		}
		record.Spec.SRv6 = migrated
	}
	return record, nil
}

func migrateSchema2SRv6(legacy *schema2SRv6Spec) (*model.SRv6Spec, error) {
	migrated := &model.SRv6Spec{
		UnderlayInterface:      legacy.UnderlayInterface,
		Table:                  legacy.Table,
		RefreshIntervalSeconds: legacy.RefreshIntervalSeconds,
	}
	usedNames := make(map[string]struct{})
	for _, source := range legacy.Sources {
		families := []struct {
			family model.SRv6AddressFamily
			suffix string
			sid    *netip.Addr
		}{
			{family: model.SRv6FamilyIPv4, suffix: "v4", sid: source.SIDv4},
			{family: model.SRv6FamilyIPv6, suffix: "v6", sid: source.SIDv6},
		}
		familyCount := 0
		for _, family := range families {
			if family.sid != nil {
				familyCount++
			}
		}
		for _, family := range families {
			if family.sid == nil {
				continue
			}
			name := source.Name
			if familyCount > 1 {
				name += "-" + family.suffix
			}
			name = uniqueSRv6SourceName(name, usedNames)
			prefixURL, err := schema2FeedURL(legacy.BaseURL, source.Name+"_"+family.suffix+".txt")
			if err != nil {
				return nil, fmt.Errorf("source %q: %w", source.Name, err)
			}
			migrated.Sources = append(migrated.Sources, model.SRv6Source{
				Name: name, Family: family.family, PrefixURL: prefixURL,
				SID: *family.sid, Priority: len(migrated.Sources) + 1, MTU: source.MTU,
			})
		}
	}
	return migrated, nil
}

func migrateSchema3(data []byte) (model.Tunnel, error) {
	var legacy schema3Tunnel
	if err := decodeSingleJSON(data, &legacy, true); err != nil {
		return model.Tunnel{}, err
	}
	if legacy.SchemaVersion != previousSchemaVersion {
		return model.Tunnel{}, fmt.Errorf("expected schema_version %d, got %d", previousSchemaVersion, legacy.SchemaVersion)
	}
	record := model.Tunnel{
		SchemaVersion: model.SchemaVersion,
		ID:            legacy.ID, Generation: legacy.Generation, Name: legacy.Name, Kind: legacy.Kind,
		Interface: legacy.Interface, Enabled: legacy.Enabled, CreatedAt: legacy.CreatedAt, UpdatedAt: legacy.UpdatedAt,
		Spec: model.Spec{
			GRE: legacy.Spec.GRE, VXLAN: legacy.Spec.VXLAN,
			WireGuard: legacy.Spec.WireGuard, AmneziaWG: legacy.Spec.AmneziaWG,
			XFRMStatic: legacy.Spec.XFRMStatic, XFRMIKEv2: legacy.Spec.XFRMIKEv2,
		},
	}
	if legacy.Spec.SRv6 != nil {
		sources := append([]model.SRv6Source(nil), legacy.Spec.SRv6.Sources...)
		normalizeLegacySRv6SourcePriorities(sources)
		record.Spec.SRv6 = &model.SRv6Spec{
			UnderlayInterface: legacy.Spec.SRv6.UnderlayInterface,
			Table:             legacy.Spec.SRv6.Table, RefreshIntervalSeconds: legacy.Spec.SRv6.RefreshIntervalSeconds,
			Sources: sources,
		}
	}
	return record, nil
}

func normalizeLegacySRv6SourcePriorities(sources []model.SRv6Source) {
	order := make([]int, len(sources))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(i, j int) bool {
		return sources[order[i]].Priority > sources[order[j]].Priority
	})
	for rank, index := range order {
		sources[index].Priority = rank + 1
	}
}

func schema2FeedURL(baseURL, filename string) (string, error) {
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return "", fmt.Errorf("parse base_url: %w", err)
	}
	return base.ResolveReference(&url.URL{Path: filename}).String(), nil
}

func uniqueSRv6SourceName(preferred string, used map[string]struct{}) string {
	for attempt := 1; ; attempt++ {
		suffix := ""
		if attempt > 1 {
			suffix = "-" + strconv.Itoa(attempt)
		}
		limit := 64 - len(suffix)
		base := preferred
		if len(base) > limit {
			base = base[:limit]
		}
		candidate := base + suffix
		if _, exists := used[candidate]; !exists {
			used[candidate] = struct{}{}
			return candidate
		}
	}
}

func decodeSingleJSON(data []byte, target any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}
