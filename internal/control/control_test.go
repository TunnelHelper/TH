package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/backup"
	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/store"
)

func TestServerAPIContracts(t *testing.T) {
	manager := &stubManager{view: model.TunnelView{Tunnel: model.Tunnel{ID: "11111111-2222-4333-8444-555555555555", Generation: 3, Name: "test"}}}
	server := httptest.NewServer(NewServer(manager).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/tunnels")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-TH-API") != APIVersion {
		t.Fatalf("list status/header = %d/%q", response.StatusCode, response.Header.Get("X-TH-API"))
	}
	response.Body.Close()
	response, err = http.Post(server.URL+"/v1/tunnels/"+manager.view.Tunnel.ID+"/observe", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || manager.observeCalls != 1 {
		t.Fatalf("observe status/calls = %d/%d", response.StatusCode, manager.observeCalls)
	}
	response, err = http.Post(server.URL+"/v1/observe", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || manager.observeAllCalls != 1 {
		t.Fatalf("observe-all status/calls = %d/%d", response.StatusCode, manager.observeAllCalls)
	}

	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/tunnels/"+manager.view.Tunnel.ID, nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusBadRequest, "invalid_request")

	manager.updateErr = store.ErrConflict
	body, _ := json.Marshal(updateRequest{Generation: 3, Tunnel: manager.view.Tunnel})
	request, _ = http.NewRequest(http.MethodPut, server.URL+"/v1/tunnels/"+manager.view.Tunnel.ID, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusConflict, "generation_conflict")

	response, err = http.Post(server.URL+"/v1/tunnels", "application/json", bytes.NewBufferString(`{"unknown":true}`))
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusBadRequest, "invalid_request")

	manager.getErr = store.ErrNotFound
	response, err = http.Get(server.URL + "/v1/tunnels/missing")
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusNotFound, "not_found")

	response, err = http.Get(server.URL + "/v1/unknown")
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusNotFound, "not_found")

	response, err = http.Post(server.URL+"/v1/admin/backup", "application/json", bytes.NewBufferString(`{"passphrase":"root backup passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusForbidden, "forbidden")
}

func TestHealthReadinessUsesConfiguredTunnels(t *testing.T) {
	tests := []struct {
		name      string
		views     []model.TunnelView
		health    map[model.Kind]core.BackendHealth
		mptcp     core.MptcpHealth
		babel     core.BabelHealth
		wantReady bool
		wantReq   bool
	}{
		{
			name:      "unused optional backend unavailable",
			views:     []model.TunnelView{},
			health:    map[model.Kind]core.BackendHealth{model.KindAmneziaWG: {Available: false, Message: "missing"}},
			wantReady: true,
		},
		{
			name: "required backend unavailable",
			views: []model.TunnelView{{
				Tunnel: model.Tunnel{Kind: model.KindAmneziaWG, Enabled: true},
				Status: model.Status{Phase: model.PhaseReady},
			}},
			health:    map[model.Kind]core.BackendHealth{model.KindAmneziaWG: {Available: false, Message: "missing"}},
			wantReady: false,
			wantReq:   true,
		},
		{
			name: "configured tunnel pending",
			views: []model.TunnelView{{
				Tunnel: model.Tunnel{Kind: model.KindGRE, Enabled: true},
				Status: model.Status{Phase: model.PhasePending},
			}},
			health:    map[model.Kind]core.BackendHealth{model.KindGRE: {Available: true}},
			mptcp:     core.MptcpHealth{Supported: true, Enabled: true, Status: "enabled", Endpoints: 2},
			babel:     core.BabelHealth{RouterID: "0011223344556677"},
			wantReady: false,
			wantReq:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &stubManager{views: test.views, health: test.health, mptcpHealth: test.mptcp, babelHealth: test.babel}
			server := httptest.NewServer(NewServer(manager).Handler())
			defer server.Close()
			response, err := http.Get(server.URL + "/v1/health")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var health HealthResponse
			if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
				t.Fatal(err)
			}
			if health.Ready != test.wantReady {
				t.Fatalf("Ready = %t, want %t", health.Ready, test.wantReady)
			}
			for kind, item := range health.Backends {
				if item.Required != test.wantReq {
					t.Fatalf("backend %s Required = %t, want %t", kind, item.Required, test.wantReq)
				}
			}
			if health.APIVersion != APIVersion || health.SchemaVersion != model.SchemaVersion || !health.Alive {
				t.Fatalf("health metadata = %+v", health)
			}
			if health.Mptcp != test.mptcp {
				t.Fatalf("Mptcp health = %+v, want %+v", health.Mptcp, test.mptcp)
			}
			if !reflect.DeepEqual(health.Babel, test.babel) {
				t.Fatalf("Babel health = %+v, want %+v", health.Babel, test.babel)
			}
		})
	}
}

func TestMutationWaitQueryReconcilesBeforeResponse(t *testing.T) {
	manager := &stubManager{view: model.TunnelView{Tunnel: model.Tunnel{ID: "11111111-2222-4333-8444-555555555555", Generation: 1}}}
	server := httptest.NewServer(NewServer(manager).Handler())
	defer server.Close()

	response, err := http.Post(server.URL+"/v1/tunnels?wait=true", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || manager.reconcileCalls != 1 {
		t.Fatalf("status/reconcile calls = %d/%d", response.StatusCode, manager.reconcileCalls)
	}

	response, err = http.Post(server.URL+"/v1/tunnels?wait=eventually", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, response, http.StatusBadRequest, "invalid_request")
	if manager.reconcileCalls != 1 {
		t.Fatalf("invalid query mutated state; reconcile calls = %d", manager.reconcileCalls)
	}
}

func TestEventStreamSendsReplayAndLiveEvents(t *testing.T) {
	hub := core.NewEventHub(8)
	hub.Publish(core.Event{Type: core.EventStatus, TunnelID: "replayed"})
	manager := &stubManager{events: hub}
	server := httptest.NewServer(NewServer(manager).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/events?after=0")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("content type = %q", response.Header.Get("Content-Type"))
	}
	decoder := json.NewDecoder(response.Body)
	var connected, replayed, live core.Event
	if err := decoder.Decode(&connected); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&replayed); err != nil {
		t.Fatal(err)
	}
	if connected.Type != core.EventConnected || replayed.TunnelID != "replayed" {
		t.Fatalf("initial events = %+v / %+v", connected, replayed)
	}
	hub.Publish(core.Event{Type: core.EventDeleted, TunnelID: "live"})
	if err := decoder.Decode(&live); err != nil {
		t.Fatal(err)
	}
	if live.Type != core.EventDeleted || live.TunnelID != "live" {
		t.Fatalf("live event = %+v", live)
	}
}

func TestSettingsAPI(t *testing.T) {
	defaults := config.Defaults()
	manager := &stubManager{babelSettings: defaults.Babel, mptcpSettings: defaults.Mptcp}
	server := httptest.NewServer(NewServer(manager).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/settings")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/settings = %d, want 200", response.StatusCode)
	}
	response.Body.Close()

	body := `{"babel":{"router_id":"0011223344556677","route_table":100,"multipath_slack":256},"mptcp":{"enabled":true,"scheduler":"roundrobin"}}`
	request, err := http.NewRequest(http.MethodPut, server.URL+"/v1/settings", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/settings = %d, want 200", response.StatusCode)
	}
	var updated DaemonSettings
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if updated.Babel.RouterID != "0011223344556677" || updated.Babel.MultipathSlack != 256 {
		t.Fatalf("updated settings = %+v", updated)
	}
	if !updated.Mptcp.Enabled || updated.Mptcp.Scheduler != "roundrobin" {
		t.Fatalf("updated MPTCP settings = %+v, want enabled roundrobin", updated.Mptcp)
	}
	if manager.babelSettings.RouterID != "0011223344556677" {
		t.Fatal("manager must receive the updated settings")
	}
	if manager.babelSettings.DelayProbeIntervalMillis != defaults.Babel.DelayProbeIntervalMillis ||
		manager.babelSettings.DelaySampleMaxAgeMillis != defaults.Babel.DelaySampleMaxAgeMillis ||
		manager.babelSettings.DelaySmoothingTimeConstantMillis != defaults.Babel.DelaySmoothingTimeConstantMillis ||
		manager.babelSettings.WeightJitterExponent != defaults.Babel.WeightJitterExponent {
		t.Fatalf("fields omitted by an older client were not preserved: %+v", manager.babelSettings)
	}
	if !manager.mptcpSettings.Enabled || manager.mptcpSettings.Scheduler != "roundrobin" {
		t.Fatalf("manager MPTCP settings = %+v", manager.mptcpSettings)
	}
}

func TestSettingsAPICanClearValues(t *testing.T) {
	current := config.Defaults()
	current.Babel.RouterID = "0011223344556677"
	current.Babel.RouteTable = 100
	current.Babel.Advertise.AdvertisedPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	current.Babel.Advertise.Include = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	current.Mptcp.Enabled = true
	current.Mptcp.Scheduler = "roundrobin"
	manager := &stubManager{babelSettings: current.Babel, mptcpSettings: current.Mptcp}
	server := httptest.NewServer(NewServer(manager).Handler())
	defer server.Close()

	desired := config.Defaults()
	payload, err := json.Marshal(DaemonSettings{Babel: desired.Babel, Mptcp: desired.Mptcp})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, server.URL+"/v1/settings", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/settings = %d, want 200", response.StatusCode)
	}
	if manager.babelSettings.RouterID != "" || manager.babelSettings.RouteTable != 0 ||
		len(manager.babelSettings.Advertise.AdvertisedPrefixes) != 0 || len(manager.babelSettings.Advertise.Include) != 0 {
		t.Fatalf("Babel values were not cleared: %+v", manager.babelSettings)
	}
	if manager.mptcpSettings.Enabled || manager.mptcpSettings.Scheduler != "" {
		t.Fatalf("MPTCP values were not cleared: %+v", manager.mptcpSettings)
	}
}

func TestUnixServerAndTypedClient(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Unix socket ownership test requires root, as does thd")
	}
	runtimeDir := filepath.Join(t.TempDir(), "run")
	settings := config.Defaults()
	settings.RuntimeDir = runtimeDir
	settings.SocketPath = filepath.Join(runtimeDir, "control.sock")
	settings.SocketGID = os.Getgid()
	settings.RequestTimeoutSeconds = 2
	manager := &stubManager{
		view:   model.TunnelView{Tunnel: model.Tunnel{ID: "11111111-2222-4333-8444-555555555555", Generation: 1, Name: "test"}},
		events: core.NewEventHub(8),
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeUnix(ctx, settings, NewServer(manager).Handler(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	client := NewClient(settings.SocketPath, 60*time.Second)
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for {
		requestContext, requestCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, err := client.Health(requestContext)
		requestCancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Unix API did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	requestContext, requestCancel := context.WithTimeout(context.Background(), time.Second)
	views, err := client.List(requestContext)
	requestCancel()
	if err != nil || len(views) != 1 || views[0].Tunnel.Name != "test" {
		t.Fatalf("typed List = %+v, %v", views, err)
	}
	streamContext, streamCancel := context.WithCancel(context.Background())
	events, streamErrors, err := client.WatchEvents(streamContext, 0)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Type != core.EventConnected {
			t.Fatalf("first stream event = %+v", event)
		}
	case err := <-streamErrors:
		t.Fatalf("start event stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("event stream did not connect")
	}
	manager.events.Publish(core.Event{Type: core.EventStatus, TunnelID: "streamed"})
	select {
	case event := <-events:
		if event.TunnelID != "streamed" {
			t.Fatalf("stream event = %+v", event)
		}
	case err := <-streamErrors:
		t.Fatalf("read event stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("live event was not streamed")
	}
	streamCancel()
	adminContext, adminCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer adminCancel()
	var encryptedBackup bytes.Buffer
	if err := client.Backup(adminContext, "root backup passphrase", &encryptedBackup); err != nil {
		t.Fatalf("backup through root Unix peer: %v", err)
	}
	if encryptedBackup.Len() == 0 {
		t.Fatal("backup response is empty")
	}
	if _, err := client.RestoreBackup(adminContext, "root backup passphrase", bytes.NewReader(encryptedBackup.Bytes()), true, false); err != nil {
		t.Fatalf("restore check through root Unix peer: %v", err)
	}
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Unix API did not shut down")
	}
	if _, err := os.Lstat(settings.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after shutdown: %v", err)
	}
}

func TestWriteErrorClassification(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid", err: core.ErrInvalidRequest, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "operation", err: core.ErrOperationFailed, status: http.StatusServiceUnavailable, code: "operation_failed"},
		{name: "internal", err: errors.New("disk failure"), status: http.StatusInternalServerError, code: "internal_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeError(recorder, test.err)
			assertAPIError(t, recorder.Result(), test.status, test.code)
		})
	}
}

func assertAPIError(t *testing.T, response *http.Response, status int, code string) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("status = %d, want %d", response.StatusCode, status)
	}
	var envelope errorEnvelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code {
		t.Fatalf("error code = %q, want %q", envelope.Error.Code, code)
	}
}

type stubManager struct {
	view              model.TunnelView
	views             []model.TunnelView
	health            map[model.Kind]core.BackendHealth
	mptcpHealth       core.MptcpHealth
	babelHealth       core.BabelHealth
	events            *core.EventHub
	babelSettings     config.BabelSettings
	mptcpSettings     config.MptcpSettings
	getErr            error
	updateErr         error
	updateSettingsErr error
	observeCalls      int
	observeAllCalls   int
	reconcileCalls    int
}

func (m *stubManager) List() ([]model.TunnelView, error) {
	if m.views != nil {
		return m.views, nil
	}
	return []model.TunnelView{m.view}, nil
}
func (m *stubManager) Get(string) (model.TunnelView, error) {
	return m.view, m.getErr
}
func (m *stubManager) Create(context.Context, model.Tunnel) (model.TunnelView, error) {
	return m.view, nil
}
func (m *stubManager) Update(context.Context, string, uint64, model.Tunnel) (model.TunnelView, error) {
	return m.view, m.updateErr
}
func (m *stubManager) SetEnabled(context.Context, string, uint64, bool) (model.TunnelView, error) {
	return m.view, nil
}
func (m *stubManager) Delete(context.Context, string, uint64) error { return nil }
func (m *stubManager) Observe(context.Context, string) (model.TunnelView, error) {
	m.observeCalls++
	return m.view, nil
}
func (m *stubManager) ObserveAll(context.Context) ([]model.TunnelView, error) {
	m.observeAllCalls++
	return []model.TunnelView{m.view}, nil
}
func (m *stubManager) Reconcile(context.Context, string) (model.TunnelView, error) {
	m.reconcileCalls++
	return m.view, nil
}
func (m *stubManager) ReconcileAll(context.Context) ([]model.TunnelView, error) {
	return []model.TunnelView{m.view}, nil
}
func (m *stubManager) Health(context.Context) map[model.Kind]core.BackendHealth {
	if m.health != nil {
		return m.health
	}
	return map[model.Kind]core.BackendHealth{model.KindGRE: {Available: true}}
}
func (m *stubManager) MptcpHealth() core.MptcpHealth { return m.mptcpHealth }
func (m *stubManager) BabelHealth() core.BabelHealth { return m.babelHealth }
func (m *stubManager) SubscribeEvents(after uint64) core.EventSubscription {
	if m.events == nil {
		m.events = core.NewEventHub(8)
	}
	return m.events.Subscribe(after)
}
func (m *stubManager) PlanBundle(model.Bundle, bool) (core.BundlePlan, error) {
	return core.BundlePlan{BundleVersion: model.BundleVersion}, nil
}
func (m *stubManager) ApplyBundle(context.Context, model.Bundle, bool, bool) (core.BundleApplyResult, error) {
	return core.BundleApplyResult{}, nil
}
func (m *stubManager) BuildBackup() (backup.Archive, error) {
	archive := backup.Archive{
		FormatVersion: backup.FormatVersion, ProductVersion: "test", SchemaVersion: model.SchemaVersion, CreatedAt: time.Now().UTC(),
	}
	if err := backup.SealArchive(&archive); err != nil {
		return backup.Archive{}, err
	}
	return archive, nil
}
func (m *stubManager) RestoreBackup(context.Context, backup.Archive, bool, bool) (core.RestoreResult, error) {
	return core.RestoreResult{}, nil
}

func (m *stubManager) Settings() (config.Settings, error) {
	settings := config.Defaults()
	settings.Babel = m.babelSettings
	return settings, nil
}

func (m *stubManager) UpdateSettings(_ context.Context, settings config.Settings) error {
	if m.updateSettingsErr != nil {
		return m.updateSettingsErr
	}
	m.babelSettings = settings.Babel
	m.mptcpSettings = settings.Mptcp
	return nil
}
