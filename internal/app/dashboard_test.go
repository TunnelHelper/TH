package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/ui"
)

func TestDashboardRefreshUsesReadOnlyListEndpoint(t *testing.T) {
	var observeCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tunnels", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"tunnels": []model.TunnelView{{Tunnel: model.Tunnel{ID: "one", Name: "one"}}}})
	})
	mux.HandleFunc("POST /v1/observe", func(writer http.ResponseWriter, _ *http.Request) {
		observeCalls.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	})
	socketPath := filepath.Join(t.TempDir(), "th.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	client := control.NewClient(socketPath, time.Second)
	t.Cleanup(client.CloseIdleConnections)
	message, ok := (dashboardModel{ctx: context.Background(), client: client, timeout: time.Second}).loadViews()().(dashboardViewsMsg)
	if !ok || message.err != nil || len(message.views) != 1 {
		t.Fatalf("dashboard refresh = %#v", message)
	}
	if observeCalls.Load() != 0 {
		t.Fatalf("dashboard refresh called observe %d times", observeCalls.Load())
	}
}

func TestDashboardUpsertSortAndDelete(t *testing.T) {
	modelState := dashboardModel{views: []model.TunnelView{{Tunnel: model.Tunnel{ID: "b", Name: "bravo"}}}}
	modelState.upsert(model.TunnelView{Tunnel: model.Tunnel{ID: "a", Name: "alpha"}, Status: model.Status{Phase: model.PhaseReady}})
	if len(modelState.views) != 2 || modelState.views[0].Tunnel.ID != "a" {
		t.Fatalf("sorted views = %+v", modelState.views)
	}
	modelState.upsert(model.TunnelView{Tunnel: model.Tunnel{ID: "a", Name: "alpha"}, Status: model.Status{Phase: model.PhaseError}})
	if len(modelState.views) != 2 || modelState.views[0].Status.Phase != model.PhaseError {
		t.Fatalf("updated views = %+v", modelState.views)
	}
	modelState.remove("a")
	if len(modelState.views) != 1 || modelState.views[0].Tunnel.ID != "b" {
		t.Fatalf("remaining views = %+v", modelState.views)
	}
}

func TestDashboardAlwaysShowsNavigationHints(t *testing.T) {
	view := (dashboardModel{width: 40, height: 30}).View()
	for _, hint := range []string{"j/k", "r: refresh", "q/esc: back"} {
		if !strings.Contains(view, hint) {
			t.Fatalf("dashboard does not show %q:\n%s", hint, view)
		}
	}
}

func TestDashboardConsumesStatusEvent(t *testing.T) {
	status := model.Status{Phase: model.PhaseReady}
	initial := dashboardModel{views: []model.TunnelView{{Tunnel: model.Tunnel{ID: "a", Name: "old"}}}}
	state, command := initial.Update(dashboardEventMsg{event: core.Event{
		Type: core.EventStatus, TunnelID: "a", TunnelName: "alpha", TunnelKind: model.KindGRE, Enabled: true, Generation: 2, Status: &status,
	}})
	updated := state.(dashboardModel)
	if len(updated.views) != 1 || updated.views[0].Tunnel.Name != "alpha" || updated.views[0].Status.Phase != model.PhaseReady || command == nil {
		t.Fatalf("dashboard update = %+v, command nil=%t", updated.views, command == nil)
	}
}

func TestFitNeverExceedsWidth(t *testing.T) {
	for width := 1; width <= 12; width++ {
		value := fit("long-dashboard-value", width)
		if got := utf8.RuneCountInString(value); got > width {
			t.Fatalf("fit width %d produced %q with width %d", width, value, got)
		}
	}
}

func TestDashboardPeerDetailsShowLiveHandshakeAndBothCounterSources(t *testing.T) {
	handshake := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	view := model.TunnelView{
		Tunnel: model.Tunnel{Kind: model.KindWireGuard, Name: "wg"},
		Status: model.Status{
			Details: map[string]string{"link_receive_bytes": "1024", "link_transmit_bytes": "2048"},
			Peers: []model.PeerStatus{{
				PublicKey: "abcdefghijklmnop", Endpoint: "192.0.2.1:51820", LastHandshakeTime: &handshake,
				ReceiveBytes: 4096, TransmitBytes: 8192,
			}},
		},
	}
	lines := strings.Join((dashboardModel{views: []model.TunnelView{view}}).peerLines(100), "\n")
	for _, value := range []string{"Interface link: rx 1.0 KiB", handshake.Format(time.RFC3339), "WG transfer: rx 4.0 KiB"} {
		if !strings.Contains(lines, value) {
			t.Fatalf("peer details do not contain %q:\n%s", value, lines)
		}
	}
}

func TestDashboardPeerDetailsStayWithinTerminalHeight(t *testing.T) {
	peers := make([]model.PeerStatus, 3)
	for index := range peers {
		peers[index] = model.PeerStatus{PublicKey: strings.Repeat(string(rune('a'+index)), 16)}
	}
	views := make([]model.TunnelView, 8)
	for index := range views {
		views[index] = model.TunnelView{Tunnel: model.Tunnel{Name: "wg", Kind: model.KindWireGuard}, Status: model.Status{Peers: peers}}
	}
	dashboard := (dashboardModel{views: views, width: 100, height: 20}).View()
	if lines := strings.Count(dashboard, "\n") + 1; lines > 20 {
		t.Fatalf("dashboard uses %d lines in a 20-line terminal:\n%s", lines, dashboard)
	}
	if !strings.Contains(dashboard, "more peers") {
		t.Fatalf("dashboard did not report hidden peer details:\n%s", dashboard)
	}
}

func TestDashboardExpandsToTerminalHeight(t *testing.T) {
	views := make([]model.TunnelView, 30)
	for index := range views {
		views[index] = model.TunnelView{Tunnel: model.Tunnel{Name: "tunnel", Kind: model.KindGRE}}
	}
	for _, height := range []int{20, 80} {
		dashboard := (dashboardModel{views: views, width: 100, height: height}).View()
		lines := strings.Count(dashboard, "\n") + 1
		if lines > height {
			t.Fatalf("dashboard uses %d lines in a %d-line terminal:\n%s", lines, height, dashboard)
		}
		if lines < min(height, 10) {
			t.Fatalf("dashboard must use the terminal height %d, used %d:\n%s", height, lines, dashboard)
		}
	}
}

func TestShowStatusLabelsLinkAndProtocolCountersSeparately(t *testing.T) {
	handshake := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	view := model.TunnelView{
		Tunnel: model.Tunnel{Name: "wg", Kind: model.KindWireGuard},
		Status: model.Status{
			Details: map[string]string{
				"counter_source": "wireguard", "link_receive_bytes": "1024", "link_transmit_bytes": "2048",
				"receive_bytes": "4096", "transmit_bytes": "8192", "latest_handshake": handshake.Format(time.RFC3339),
				"link_type": "wireguard", "listen_port": "51820",
			},
			Peers: []model.PeerStatus{{PublicKey: "abcdefghijklmnop", LastHandshakeTime: &handshake, ReceiveBytes: 4096, TransmitBytes: 8192}},
		},
	}
	var output bytes.Buffer
	showStatus(ui.New(&output, &output, strings.NewReader("")), view)
	for _, value := range []string{"Interface link: rx=1.0 KiB", "WireGuard peer transfer total: rx=4.0 KiB", "Latest handshake: " + handshake.Format(time.RFC3339), "Transfer: rx=4.0 KiB", "Link type: wireguard", "Listen port: 51820"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("status does not contain %q:\n%s", value, output.String())
		}
	}
}

func TestParseAfterOption(t *testing.T) {
	after, err := parseAfterOption([]string{"watch", "--after", "42"})
	if err != nil || after != 42 {
		t.Fatalf("after = %d, %v", after, err)
	}
	if _, err := parseAfterOption([]string{"watch", "--after", "bad"}); err == nil {
		t.Fatal("invalid sequence was accepted")
	}
}
