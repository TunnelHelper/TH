//go:build linux

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestDaemonLoggerOmitsJournalTimestamp(t *testing.T) {
	var output bytes.Buffer
	logger := newDaemonLogger(&output)
	logger.Info("control API listening", "socket", "/run/th/control.sock")
	slog.NewLogLogger(logger.Handler(), slog.LevelWarn).Print("HTTP server warning")
	line := output.String()
	if strings.Contains(line, "time=") {
		t.Fatalf("daemon log contains a duplicate timestamp: %q", line)
	}
	for _, expected := range []string{"level=INFO", "msg=\"control API listening\"", "socket=/run/th/control.sock"} {
		if !strings.Contains(line, expected) {
			t.Fatalf("daemon log does not contain %q: %q", expected, line)
		}
	}
	if !strings.Contains(line, "level=WARN msg=\"HTTP server warning\"") {
		t.Fatalf("bridged HTTP log lost its structured fields: %q", line)
	}
}
