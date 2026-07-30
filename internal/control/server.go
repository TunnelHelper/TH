package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/TunnelHelper/TH/internal/backup"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/version"
)

const APIVersion = "v1"

type Manager interface {
	List() ([]model.TunnelView, error)
	Get(string) (model.TunnelView, error)
	Create(context.Context, model.Tunnel) (model.TunnelView, error)
	Update(context.Context, string, uint64, model.Tunnel) (model.TunnelView, error)
	SetEnabled(context.Context, string, uint64, bool) (model.TunnelView, error)
	Delete(context.Context, string, uint64) error
	Observe(context.Context, string) (model.TunnelView, error)
	ObserveAll(context.Context) ([]model.TunnelView, error)
	Reconcile(context.Context, string) (model.TunnelView, error)
	ReconcileAll(context.Context) ([]model.TunnelView, error)
	Health(context.Context) map[model.Kind]core.BackendHealth
	SubscribeEvents(uint64) core.EventSubscription
	PlanBundle(model.Bundle, bool) (core.BundlePlan, error)
	ApplyBundle(context.Context, model.Bundle, bool, bool) (core.BundleApplyResult, error)
	BuildBackup() (backup.Archive, error)
	RestoreBackup(context.Context, backup.Archive, bool, bool) (core.RestoreResult, error)
}

type Server struct {
	manager Manager
	mux     *http.ServeMux
}

type updateRequest struct {
	Generation uint64       `json:"generation"`
	Tunnel     model.Tunnel `json:"tunnel"`
}

type actionRequest struct {
	Generation uint64 `json:"generation"`
}

type bundleRequest struct {
	Bundle model.Bundle `json:"bundle"`
	Prune  bool         `json:"prune"`
}

type backupRequest struct {
	Passphrase string `json:"passphrase"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type TunnelHealthSummary struct {
	Total    int `json:"total"`
	Enabled  int `json:"enabled"`
	Ready    int `json:"ready"`
	Pending  int `json:"pending"`
	Error    int `json:"error"`
	Disabled int `json:"disabled"`
}

type HealthResponse struct {
	APIVersion    string                            `json:"api_version"`
	SchemaVersion int                               `json:"schema_version"`
	Alive         bool                              `json:"alive"`
	Ready         bool                              `json:"ready"`
	Daemon        version.Info                      `json:"daemon"`
	Backends      map[model.Kind]core.BackendHealth `json:"backends"`
	Tunnels       TunnelHealthSummary               `json:"tunnels"`
}

func NewServer(manager Manager) *Server {
	server := &Server{manager: manager, mux: http.NewServeMux()}
	server.mux.HandleFunc("GET /v1/health", server.health)
	server.mux.HandleFunc("GET /v1/events", server.events)
	server.mux.HandleFunc("GET /v1/tunnels", server.list)
	server.mux.HandleFunc("POST /v1/tunnels", server.create)
	server.mux.HandleFunc("GET /v1/tunnels/{id}", server.get)
	server.mux.HandleFunc("PUT /v1/tunnels/{id}", server.update)
	server.mux.HandleFunc("DELETE /v1/tunnels/{id}", server.delete)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/enable", server.enable)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/disable", server.disable)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/reconcile", server.reconcile)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/observe", server.observe)
	server.mux.HandleFunc("POST /v1/observe", server.observeAll)
	server.mux.HandleFunc("POST /v1/reconcile", server.reconcileAll)
	server.mux.HandleFunc("POST /v1/plan", server.planBundle)
	server.mux.HandleFunc("POST /v1/apply", server.applyBundle)
	server.mux.HandleFunc("POST /v1/admin/backup", server.backup)
	server.mux.HandleFunc("POST /v1/admin/restore", server.restore)
	server.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, errorEnvelope{Error: apiError{Code: "not_found", Message: "API endpoint not found"}})
	})
	return server
}

func (s *Server) backup(w http.ResponseWriter, r *http.Request) {
	if !requireRootPeer(w, r) {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	var request backupRequest
	if err := decodeJSON(r, &request); err != nil {
		writeBadRequest(w, err)
		return
	}
	if err := backup.ValidatePassphrase(request.Passphrase); err != nil {
		writeBadRequest(w, err)
		return
	}
	archive, err := s.manager.BuildBackup()
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-TH-Backup-Format", "age+scrypt")
	w.Header().Add("Trailer", "X-TH-Backup-Error")
	if err := backup.Encrypt(w, request.Passphrase, archive); err != nil {
		w.Header().Set("X-TH-Backup-Error", err.Error())
	}
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	if !requireRootPeer(w, r) {
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
	wait, err := parseWait(r)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	check, err := parseBoolQuery(r, "check")
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	passphrase := r.Header.Get("X-TH-Backup-Passphrase")
	archive, err := backup.Decrypt(r.Body, passphrase)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	result, err := s.manager.RestoreBackup(r.Context(), archive, check, wait)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func requireRootPeer(w http.ResponseWriter, r *http.Request) bool {
	credentials, ok := PeerCredentialsFromContext(r.Context())
	if !ok || credentials.UID != 0 {
		writeJSON(w, http.StatusForbidden, errorEnvelope{Error: apiError{Code: "forbidden", Message: "root Unix peer credentials are required"}})
		return false
	}
	return true
}

func (s *Server) planBundle(w http.ResponseWriter, r *http.Request) {
	var request bundleRequest
	if err := decodeJSON(r, &request); err != nil {
		writeBadRequest(w, err)
		return
	}
	plan, err := s.manager.PlanBundle(request.Bundle, request.Prune)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) applyBundle(w http.ResponseWriter, r *http.Request) {
	wait, err := parseWait(r)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	if wait {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	}
	var request bundleRequest
	if err := decodeJSON(r, &request); err != nil {
		writeBadRequest(w, err)
		return
	}
	result, err := s.manager.ApplyBundle(r.Context(), request.Bundle, request.Prune, wait)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	after := uint64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			writeBadRequest(w, errors.New("after must be an unsigned event sequence"))
			return
		}
		after = parsed
	}
	subscription := s.manager.SubscribeEvents(after)
	defer subscription.Cancel()
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	encoder := json.NewEncoder(w)
	connected := core.Event{
		Time:    time.Now().UTC(),
		Type:    core.EventConnected,
		Details: map[string]string{"current_sequence": strconv.FormatUint(subscription.Current, 10)},
	}
	if subscription.Gap {
		connected.Message = "requested event history is no longer retained"
		connected.Details["oldest_sequence"] = strconv.FormatUint(subscription.Oldest, 10)
	}
	if err := encoder.Encode(connected); err != nil {
		return
	}
	if err := controller.Flush(); err != nil {
		return
	}
	for _, event := range subscription.Replay {
		if err := encoder.Encode(event); err != nil {
			return
		}
	}
	if err := controller.Flush(); err != nil {
		return
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-subscription.Events:
			if !ok {
				return
			}
			if err := encoder.Encode(event); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		case now := <-heartbeat.C:
			if err := encoder.Encode(core.Event{Time: now.UTC(), Type: core.EventHeartbeat}); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-TH-API", APIVersion)
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	health := s.manager.Health(r.Context())
	views, err := s.manager.List()
	if err != nil {
		writeError(w, err)
		return
	}
	ready := true
	summary := TunnelHealthSummary{Total: len(views)}
	for _, view := range views {
		if !view.Tunnel.Enabled {
			summary.Disabled++
			continue
		}
		summary.Enabled++
		item := health[view.Tunnel.Kind]
		item.Required = true
		health[view.Tunnel.Kind] = item
		if !item.Available {
			ready = false
		}
		switch view.Status.Phase {
		case model.PhaseReady:
			summary.Ready++
		case model.PhaseError:
			summary.Error++
			ready = false
		default:
			summary.Pending++
			ready = false
		}
	}
	writeJSON(w, http.StatusOK, HealthResponse{
		APIVersion:    APIVersion,
		SchemaVersion: model.SchemaVersion,
		Alive:         true,
		Ready:         ready,
		Daemon:        version.Current(),
		Backends:      health,
		Tunnels:       summary,
	})
}

func (s *Server) list(w http.ResponseWriter, _ *http.Request) {
	views, err := s.manager.List()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": views})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	view, err := s.manager.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	wait, err := parseWait(r)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	var record model.Tunnel
	if err := decodeJSON(r, &record); err != nil {
		writeBadRequest(w, err)
		return
	}
	view, err := s.manager.Create(r.Context(), record)
	if err != nil {
		writeError(w, err)
		return
	}
	if wait {
		view, err = s.manager.Reconcile(r.Context(), view.Tunnel.ID)
		if err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	wait, err := parseWait(r)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	var request updateRequest
	if err := decodeJSON(r, &request); err != nil {
		writeBadRequest(w, err)
		return
	}
	view, err := s.manager.Update(r.Context(), r.PathValue("id"), request.Generation, request.Tunnel)
	if err != nil {
		writeError(w, err)
		return
	}
	if wait {
		view, err = s.manager.Reconcile(r.Context(), view.Tunnel.ID)
		if err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	generation, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	if err := s.manager.Delete(r.Context(), r.PathValue("id"), generation); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enable(w http.ResponseWriter, r *http.Request) {
	s.setEnabled(w, r, true)
}

func (s *Server) disable(w http.ResponseWriter, r *http.Request) {
	s.setEnabled(w, r, false)
}

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	wait, err := parseWait(r)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	var request actionRequest
	if err := decodeJSON(r, &request); err != nil {
		writeBadRequest(w, err)
		return
	}
	view, err := s.manager.SetEnabled(r.Context(), r.PathValue("id"), request.Generation, enabled)
	if err != nil {
		writeError(w, err)
		return
	}
	if wait {
		view, err = s.manager.Reconcile(r.Context(), view.Tunnel.ID)
		if err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, view)
}

func parseWait(r *http.Request) (bool, error) {
	return parseBoolQuery(r, "wait")
}

func parseBoolQuery(r *http.Request, name string) (bool, error) {
	values, ok := r.URL.Query()[name]
	if !ok {
		return false, nil
	}
	if len(values) != 1 {
		return false, fmt.Errorf("%s query parameter must occur once", name)
	}
	wait, err := strconv.ParseBool(values[0])
	if err != nil {
		return false, fmt.Errorf("%s query parameter must be true or false", name)
	}
	return wait, nil
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	view, err := s.manager.Reconcile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) observe(w http.ResponseWriter, r *http.Request) {
	view, err := s.manager.Observe(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) observeAll(w http.ResponseWriter, r *http.Request) {
	views, err := s.manager.ObserveAll(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": views})
}

func (s *Server) reconcileAll(w http.ResponseWriter, r *http.Request) {
	views, err := s.manager.ReconcileAll(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": views})
}
