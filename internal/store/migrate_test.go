package store

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestOpenMigratesSchema2RecordWithoutBackup(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	record := preparedWireGuard(t, "legacy-wg", "wg-old", peerKey.PublicKey().String())
	record.SchemaVersion = legacySchemaVersion
	writeLegacyRecord(t, stateDir, record.ID, record)

	records, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := records.Get(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != model.SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", loaded.SchemaVersion, model.SchemaVersion)
	}
	if loaded.Name != "wg-legacy-wg" {
		t.Fatalf("migrated name = %q, want wg-legacy-wg", loaded.Name)
	}
	if loaded.Generation != record.Generation || loaded.UpdatedAt != record.UpdatedAt {
		t.Fatalf("migration changed record history: %+v", loaded)
	}
	if loaded.Spec.WireGuard.PrivateKey != record.Spec.WireGuard.PrivateKey {
		t.Fatal("migration did not preserve WireGuard private key")
	}
	migrations := records.Migrations()
	if len(migrations) != 1 || migrations[0].RecordID != record.ID || migrations[0].From != 2 || migrations[0].To != 3 {
		t.Fatalf("migrations = %+v", migrations)
	}
	assertNoMigrationBackups(t, stateDir)

	reopened, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if migrations := reopened.Migrations(); len(migrations) != 0 {
		t.Fatalf("reopen repeated migrations: %+v", migrations)
	}
}

func TestOpenMigratesSchema2SRv6Sources(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	id, err := model.NewID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sid4 := netip.MustParseAddr("2001:db8::4")
	sid6 := netip.MustParseAddr("2001:db8::6")
	legacy := schema2Tunnel{
		SchemaVersion: legacySchemaVersion,
		ID:            id, Generation: 7, Name: "legacy-srv6", Kind: model.KindSRv6, Enabled: true,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		Spec: schema2Spec{SRv6: &schema2SRv6Spec{
			BaseURL: "https://routes.example/feeds", UnderlayInterface: "eth0",
			Table: 1000, RefreshIntervalSeconds: 300,
			Sources: []schema2SRv6Source{{Name: "carrier", SIDv4: &sid4, SIDv6: &sid6, MTU: 1480}},
		}},
	}
	writeLegacyRecord(t, stateDir, id, legacy)

	records, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := records.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	sources := loaded.Spec.SRv6.Sources
	if len(sources) != 2 {
		t.Fatalf("migrated sources = %+v", sources)
	}
	assertMigratedSRv6Source(t, sources[0], "carrier-v4", model.SRv6FamilyIPv4, "https://routes.example/feeds/carrier_v4.txt", sid4)
	assertMigratedSRv6Source(t, sources[1], "carrier-v6", model.SRv6FamilyIPv6, "https://routes.example/feeds/carrier_v6.txt", sid6)
	if loaded.Generation != legacy.Generation || loaded.CreatedAt != legacy.CreatedAt || loaded.UpdatedAt != legacy.UpdatedAt {
		t.Fatal("SRv6 migration changed generation or timestamps")
	}
}

func TestOpenNormalizesSchema3LegacyNameWithoutBackup(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	record := preparedWireGuard(t, "legacy-v3", "wg-legacy-v3", peerKey.PublicKey().String())
	writeLegacyRecord(t, stateDir, record.ID, record)

	records, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := records.Get(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "wg-legacy-v3" || loaded.SchemaVersion != model.SchemaVersion {
		t.Fatalf("normalized record = name %q schema %d", loaded.Name, loaded.SchemaVersion)
	}
	if loaded.Generation != record.Generation || loaded.CreatedAt != record.CreatedAt || loaded.UpdatedAt != record.UpdatedAt {
		t.Fatal("name normalization changed generation or timestamps")
	}
	migrations := records.Migrations()
	if len(migrations) != 1 || migrations[0].From != 3 || migrations[0].To != 3 || migrations[0].PreviousName != "legacy-v3" || migrations[0].Name != "wg-legacy-v3" {
		t.Fatalf("migrations = %+v", migrations)
	}
	assertNoMigrationBackups(t, stateDir)

	reopened, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if migrations := reopened.Migrations(); len(migrations) != 0 {
		t.Fatalf("reopen repeated name normalization: %+v", migrations)
	}
}

func TestOpenRejectsMalformedSchema2RecordWithoutRewritingIt(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	id, err := model.NewID()
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"schema_version":2,"id":"` + id + `","unexpected":true}`)
	writeRawLegacyRecord(t, stateDir, id, original)

	if _, err := Open(stateDir); err == nil || !strings.Contains(err.Error(), `unknown field "unexpected"`) {
		t.Fatalf("Open error = %v", err)
	}
	actual, err := os.ReadFile(filepath.Join(stateDir, "tunnels", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, original) {
		t.Fatal("failed migration rewrote the original record")
	}
}

func TestOpenPreflightsEveryRecordBeforeMigrating(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	validID := "11111111-1111-4111-8111-111111111111"
	invalidID := "22222222-2222-4222-8222-222222222222"
	valid := preparedGRE(t, "legacy-gre", "gre-old")
	valid.ID = validID
	valid.SchemaVersion = legacySchemaVersion
	original := writeLegacyRecord(t, stateDir, validID, valid)
	writeRawLegacyRecord(t, stateDir, invalidID, []byte(`{"schema_version":2,"id":"`+invalidID+`","unexpected":true}`))

	if _, err := Open(stateDir); err == nil {
		t.Fatal("Open accepted a malformed record")
	}
	actual, err := os.ReadFile(filepath.Join(stateDir, "tunnels", validID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, original) {
		t.Fatal("preflight failure allowed an earlier record to be migrated")
	}
}

func TestSchema2MigrationUsesProtocolPrefixes(t *testing.T) {
	for _, test := range []struct {
		kind model.Kind
		name string
		want string
	}{
		{model.KindGRE, "edge", "gre-edge"},
		{model.KindVXLAN, "edge", "vxlan-edge"},
		{model.KindWireGuard, "edge", "wg-edge"},
		{model.KindWireGuard, "wg-edge", "wg-edge"},
		{model.KindAmneziaWG, "edge", "awg-edge"},
		{model.KindXFRMStatic, "edge", "ipsec-edge"},
		{model.KindXFRMIKEv2, "edge", "ipsec-edge"},
		{model.KindSRv6, "edge", "edge"},
	} {
		if got := model.PrefixedTunnelName(test.kind, test.name); got != test.want {
			t.Errorf("PrefixedTunnelName(%q, %q) = %q, want %q", test.kind, test.name, got, test.want)
		}
	}
}

func assertMigratedSRv6Source(t *testing.T, source model.SRv6Source, name string, family model.SRv6AddressFamily, prefixURL string, sid netip.Addr) {
	t.Helper()
	if source.Name != name || source.Family != family || source.PrefixURL != prefixURL || source.SID != sid || source.Priority != 0 || source.MTU != 1480 {
		t.Fatalf("migrated source = %+v", source)
	}
}

func writeLegacyRecord(t *testing.T, stateDir, id string, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	writeRawLegacyRecord(t, stateDir, id, data)
	return data
}

func writeRawLegacyRecord(t *testing.T, stateDir, id string, data []byte) {
	t.Helper()
	dir := filepath.Join(stateDir, "tunnels")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertNoMigrationBackups(t *testing.T, stateDir string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(stateDir, "tunnels"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bak") {
			t.Fatalf("migration retained backup %q", entry.Name())
		}
	}
}
