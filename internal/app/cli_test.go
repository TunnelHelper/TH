package app

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
)

func TestReadTunnelAcceptsBareRecordAndAPIView(t *testing.T) {
	record := model.Tunnel{
		Name: "gre", Kind: model.KindGRE, Interface: "gre0",
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"record": record,
		"view":   model.TunnelView{Tunnel: record, Status: model.Status{TunnelID: record.ID}},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tunnel.json")
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := readTunnel(path)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.ID != record.ID || loaded.Name != record.Name {
				t.Fatalf("loaded = %+v", loaded)
			}
		})
	}
}

func TestReadTunnelRejectsMultipleJSONValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel.json")
	if err := os.WriteFile(path, []byte("{}\n{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTunnel(path); err == nil {
		t.Fatal("multiple JSON values were accepted")
	}
}

func TestDiagnoseMissingSocket(t *testing.T) {
	report := diagnose(t.Context(), filepath.Join(t.TempDir(), "missing.sock"), nil)
	if report.OK || len(report.Checks) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if report.Checks[0].Name != "control_socket" || report.Checks[0].Status != "fail" {
		t.Fatalf("check = %+v", report.Checks[0])
	}
}

func TestParseWaitOption(t *testing.T) {
	positionals, wait, err := parseWaitOption([]string{"create", "record.json", "--wait"})
	if err != nil || !wait || len(positionals) != 2 || positionals[1] != "record.json" {
		t.Fatalf("parsed = %v, %t, %v", positionals, wait, err)
	}
	if _, _, err := parseWaitOption([]string{"create", "--wait", "--wait", "record.json"}); err == nil {
		t.Fatal("duplicate --wait was accepted")
	}
}

func TestDecodeBundleAcceptsSingleArrayAndEnvelope(t *testing.T) {
	record := model.Tunnel{
		Name: "gre", Kind: model.KindGRE, Interface: "gre0",
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	}
	for name, value := range map[string]any{
		"single":   record,
		"array":    []model.Tunnel{record},
		"envelope": model.Bundle{BundleVersion: model.BundleVersion, Tunnels: []model.Tunnel{record}},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := decodeBundleData(data)
			if err != nil {
				t.Fatal(err)
			}
			if bundle.BundleVersion != model.BundleVersion || len(bundle.Tunnels) != 1 || bundle.Tunnels[0].Name != record.Name {
				t.Fatalf("bundle = %+v", bundle)
			}
		})
	}
}

func TestReadBundleDirectoryFlattensSortedJSONFiles(t *testing.T) {
	directory := t.TempDir()
	for name, recordName := range map[string]string{"02.json": "bravo", "01.json": "alpha"} {
		data, err := json.Marshal(model.Tunnel{
			Name: recordName, Kind: model.KindGRE, Interface: "gre-" + recordName,
			Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundle, err := readBundle(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Tunnels) != 2 || bundle.Tunnels[0].Name != "alpha" || bundle.Tunnels[1].Name != "bravo" {
		t.Fatalf("directory bundle = %+v", bundle.Tunnels)
	}
}

func TestDecodeBundleRejectsUnknownEnvelopeField(t *testing.T) {
	if _, err := decodeBundleData([]byte(`{"bundle_version":1,"tunnels":[],"unknown":true}`)); err == nil {
		t.Fatal("unknown bundle field was accepted")
	}
}

func TestParseBundleCommand(t *testing.T) {
	path, prune, wait, err := parseBundleCommand([]string{"apply", "--prune", "records", "--wait"})
	if err != nil || path != "records" || !prune || !wait {
		t.Fatalf("parsed bundle command = %q, %t, %t, %v", path, prune, wait, err)
	}
	if _, _, _, err := parseBundleCommand([]string{"apply", "one", "two"}); err == nil {
		t.Fatal("multiple bundle paths were accepted")
	}
}
