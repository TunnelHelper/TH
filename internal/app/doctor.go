package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/version"
)

var ErrDoctorFailed = errors.New("doctor found problems")

type doctorCheck struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

type doctorReport struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

func diagnose(ctx context.Context, socketPath string, client *control.Client) doctorReport {
	report := doctorReport{OK: true}
	add := func(check doctorCheck) {
		report.Checks = append(report.Checks, check)
		if check.Status == "fail" {
			report.OK = false
		}
	}

	info, err := os.Lstat(socketPath)
	if err != nil {
		add(doctorCheck{Name: "control_socket", Status: "fail", Message: err.Error(), Suggestion: "check systemctl status thd.service"})
		return report
	}
	if info.Mode()&os.ModeSocket == 0 {
		add(doctorCheck{Name: "control_socket", Status: "fail", Message: fmt.Sprintf("%s is not a Unix socket", socketPath), Suggestion: "remove the stale path and restart thd.service"})
		return report
	}
	add(doctorCheck{Name: "control_socket", Status: "pass", Message: socketPath})

	health, err := client.Health(ctx)
	if err != nil {
		add(doctorCheck{Name: "daemon", Status: "fail", Message: err.Error(), Suggestion: "check socket permissions and systemctl status thd.service"})
		return report
	}
	add(doctorCheck{Name: "daemon", Status: "pass", Message: "thd API is reachable"})
	if health.APIVersion != control.APIVersion {
		add(doctorCheck{Name: "api_version", Status: "fail", Message: fmt.Sprintf("client expects %s, daemon provides %s", control.APIVersion, health.APIVersion), Suggestion: "install matching th and thd versions"})
	} else {
		add(doctorCheck{Name: "api_version", Status: "pass", Message: health.APIVersion})
	}
	if health.SchemaVersion != model.SchemaVersion {
		add(doctorCheck{Name: "schema_version", Status: "fail", Message: fmt.Sprintf("client expects %d, daemon provides %d", model.SchemaVersion, health.SchemaVersion), Suggestion: "review release migration notes before changing packages"})
	} else {
		add(doctorCheck{Name: "schema_version", Status: "pass", Message: fmt.Sprintf("%d", health.SchemaVersion)})
	}
	clientVersion := version.Current()
	versionStatus := "pass"
	versionSuggestion := ""
	if clientVersion.Version == "dev" || health.Daemon.Version == "dev" {
		versionStatus = "warn"
	} else if clientVersion.Version != health.Daemon.Version {
		versionStatus = "warn"
		versionSuggestion = "install matching th and thd package versions"
	}
	add(doctorCheck{
		Name:       "binary_versions",
		Status:     versionStatus,
		Message:    fmt.Sprintf("th=%s (%s), thd=%s (%s)", clientVersion.Version, clientVersion.Commit, health.Daemon.Version, health.Daemon.Commit),
		Suggestion: versionSuggestion,
	})

	kinds := append([]model.Kind(nil), model.Kinds...)
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	for _, kind := range kinds {
		item, ok := health.Backends[kind]
		if !ok || item.Available {
			continue
		}
		status := "warn"
		suggestion := "install or enable this backend only if it is needed"
		if item.Required {
			status = "fail"
			suggestion = "provide the required kernel or control-plane capability, then run th reconcile"
		}
		add(doctorCheck{Name: "backend_" + string(kind), Status: status, Message: shortUnavailableWarning(kind, item), Suggestion: suggestion})
	}

	if health.Ready {
		add(doctorCheck{Name: "configured_tunnels", Status: "pass", Message: fmt.Sprintf("%d enabled, %d ready", health.Tunnels.Enabled, health.Tunnels.Ready)})
	} else {
		add(doctorCheck{
			Name:       "configured_tunnels",
			Status:     "fail",
			Message:    fmt.Sprintf("%d ready, %d pending, %d error", health.Tunnels.Ready, health.Tunnels.Pending, health.Tunnels.Error),
			Suggestion: "inspect th list and run th reconcile after correcting the reported condition",
		})
	}
	return report
}
