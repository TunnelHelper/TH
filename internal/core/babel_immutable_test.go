package core

import (
	"net/netip"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
)

func TestBabelRouteTableIsImmutable(t *testing.T) {
	now := time.Now().UTC()
	base := model.Tunnel{
		SchemaVersion: model.SchemaVersion,
		ID:            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		Generation:    1,
		Name:          "mesh",
		Kind:          model.KindBabel,
		CreatedAt:     now,
		UpdatedAt:     now,
		Spec: model.Spec{Babel: &model.BabelSpec{
			Interfaces:         []string{"wg0"},
			AdvertisedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			RouterID:           "0011223344556677",
		}},
	}
	current := base
	next := base
	next.Spec = model.Spec{Babel: &model.BabelSpec{
		Interfaces:         append([]string(nil), base.Spec.Babel.Interfaces...),
		AdvertisedPrefixes: append([]netip.Prefix(nil), base.Spec.Babel.AdvertisedPrefixes...),
		RouterID:           base.Spec.Babel.RouterID,
	}}
	next.Generation = 2

	if err := validateStableOwnership(current, next); err != nil {
		t.Fatalf("identical route tables must be allowed: %v", err)
	}

	next.Spec.Babel.RouteTable = 100
	if err := validateStableOwnership(current, next); err == nil {
		t.Fatal("changing the Babel route table must be rejected")
	}
}
