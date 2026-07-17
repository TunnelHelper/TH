package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sudogeeker/tunnel-helper/internal/core"
	"github.com/sudogeeker/tunnel-helper/internal/model"
)

const APIVersion = "v1"

type Manager interface {
	List() ([]model.TunnelView, error)
	Get(string) (model.TunnelView, error)
	Create(context.Context, model.Tunnel) (model.TunnelView, error)
	Update(context.Context, string, uint64, model.Tunnel) (model.TunnelView, error)
	SetEnabled(context.Context, string, uint64, bool) (model.TunnelView, error)
	Delete(context.Context, string, uint64) error
	Reconcile(context.Context, string) (model.TunnelView, error)
	ReconcileAll(context.Context) ([]model.TunnelView, error)
	Health(context.Context) map[model.Kind]core.BackendHealth
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

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewServer(manager Manager) *Server {
	server := &Server{manager: manager, mux: http.NewServeMux()}
	server.mux.HandleFunc("GET /v1/health", server.health)
	server.mux.HandleFunc("GET /v1/tunnels", server.list)
	server.mux.HandleFunc("POST /v1/tunnels", server.create)
	server.mux.HandleFunc("GET /v1/tunnels/{id}", server.get)
	server.mux.HandleFunc("PUT /v1/tunnels/{id}", server.update)
	server.mux.HandleFunc("DELETE /v1/tunnels/{id}", server.delete)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/enable", server.enable)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/disable", server.disable)
	server.mux.HandleFunc("POST /v1/tunnels/{id}/reconcile", server.reconcile)
	server.mux.HandleFunc("POST /v1/reconcile", server.reconcileAll)
	server.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, errorEnvelope{Error: apiError{Code: "not_found", Message: "API endpoint not found"}})
	})
	return server
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Tunnel-Helper-API", APIVersion)
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	health := s.manager.Health(r.Context())
	ready := true
	for _, item := range health {
		if !item.Available {
			ready = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_version": APIVersion,
		"ready":       ready,
		"backends":    health,
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
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	view, err := s.manager.Reconcile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) reconcileAll(w http.ResponseWriter, r *http.Request) {
	views, err := s.manager.ReconcileAll(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": views})
}

func decodeJSON(r *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, (4<<20)+1))
	if err != nil {
		return fmt.Errorf("read JSON body: %w", err)
	}
	if len(data) > 4<<20 {
		return errors.New("JSON body exceeds 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("JSON body must contain exactly one value")
	}
	return nil
}

func parseIfMatch(value string) (uint64, error) {
	value = strings.Trim(value, "\" ")
	if value == "" {
		return 0, errors.New("If-Match generation header is required")
	}
	generation, err := strconv.ParseUint(value, 10, 64)
	if err != nil || generation == 0 {
		return 0, errors.New("If-Match must contain a positive generation")
	}
	return generation, nil
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	switch {
	case core.IsNotFound(err):
		status, code = http.StatusNotFound, "not_found"
	case core.IsConflict(err):
		status, code = http.StatusConflict, "generation_conflict"
	case core.IsInvalidRequest(err):
		status, code = http.StatusBadRequest, "invalid_request"
	case core.IsOperationFailed(err):
		status, code = http.StatusServiceUnavailable, "operation_failed"
	}
	writeJSON(w, status, errorEnvelope{Error: apiError{Code: code, Message: err.Error()}})
}

func writeBadRequest(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, errorEnvelope{Error: apiError{Code: "invalid_request", Message: err.Error()}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
