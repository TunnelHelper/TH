package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TunnelHelper/TH/internal/core"
)

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
