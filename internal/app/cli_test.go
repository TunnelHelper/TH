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
