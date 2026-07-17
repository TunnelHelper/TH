package app

import (
	"testing"
	"unicode/utf8"

	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/model"
)

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

func TestParseAfterOption(t *testing.T) {
	after, err := parseAfterOption([]string{"watch", "--after", "42"})
	if err != nil || after != 42 {
		t.Fatalf("after = %d, %v", after, err)
	}
	if _, err := parseAfterOption([]string{"watch", "--after", "bad"}); err == nil {
		t.Fatal("invalid sequence was accepted")
	}
}
