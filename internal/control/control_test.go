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

	"github.com/sudogeeker/tunnel-helper/internal/config"
	"github.com/sudogeeker/tunnel-helper/internal/core"
	"github.com/sudogeeker/tunnel-helper/internal/model"
	"github.com/sudogeeker/tunnel-helper/internal/store"
)

func TestServerAPIContracts(t *testing.T) {
	manager := &stubManager{view: model.TunnelView{Tunnel: model.Tunnel{ID: "11111111-2222-4333-8444-555555555555", Generation: 3, Name: "test"}}}
	server := httptest.NewServer(NewServer(manager).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/tunnels")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Tunnel-Helper-API") != APIVersion {
		t.Fatalf("list status/header = %d/%q", response.StatusCode, response.Header.Get("X-Tunnel-Helper-API"))
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

func TestUnixServerAndTypedClient(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Unix socket ownership test requires root, as does tunnel-helperd")
	}
	runtimeDir := filepath.Join(t.TempDir(), "run")
	settings := config.Defaults()
	settings.RuntimeDir = runtimeDir
	settings.SocketPath = filepath.Join(runtimeDir, "control.sock")
	settings.SocketGID = os.Getgid()
	settings.RequestTimeoutSeconds = 2
	manager := &stubManager{view: model.TunnelView{Tunnel: model.Tunnel{ID: "11111111-2222-4333-8444-555555555555", Generation: 1, Name: "test"}}}
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
	view      model.TunnelView
	getErr    error
	updateErr error
}

func (m *stubManager) List() ([]model.TunnelView, error) { return []model.TunnelView{m.view}, nil }
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
	return m.view, nil
}
func (m *stubManager) ReconcileAll(context.Context) ([]model.TunnelView, error) {
	return []model.TunnelView{m.view}, nil
}
func (m *stubManager) Health(context.Context) map[model.Kind]core.BackendHealth {
	return map[model.Kind]core.BackendHealth{model.KindGRE: {Available: true}}
}
