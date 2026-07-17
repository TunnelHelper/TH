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
	"os"
	"path/filepath"
	"testing"
	"time"

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
}

func TestHealthReadinessUsesConfiguredTunnels(t *testing.T) {
	tests := []struct {
		name      string
		views     []model.TunnelView
		health    map[model.Kind]core.BackendHealth
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
			wantReady: false,
			wantReq:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &stubManager{views: test.views, health: test.health}
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
	client := NewClient(settings.SocketPath, 2*time.Second)
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
	view           model.TunnelView
	views          []model.TunnelView
	health         map[model.Kind]core.BackendHealth
	events         *core.EventHub
	getErr         error
	updateErr      error
	reconcileCalls int
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
func (m *stubManager) SubscribeEvents(after uint64) core.EventSubscription {
	if m.events == nil {
		m.events = core.NewEventHub(8)
	}
	return m.events.Subscribe(after)
}
