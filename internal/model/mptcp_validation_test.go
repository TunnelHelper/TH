package model

import (
	"net/netip"
	"testing"
	"time"
)

func newMptcpTunnel() *Tunnel {
	record := newBabelTunnel()
	record.Spec.Babel = nil
	record.Spec.Mptcp = &MptcpTunnelConfig{}
	return record
}

func TestValidateMptcpTunnelTriState(t *testing.T) {
	// nil follows the global switch and must validate.
	record := newMptcpTunnel()
	record.Spec.Mptcp = nil
	if err := Validate(record); err != nil {
		t.Fatalf("nil endpoint switch must validate: %v", err)
	}

	// Explicit true and false are both legal.
	for _, value := range []bool{true, false} {
		record = newMptcpTunnel()
		record.Spec.Mptcp.Endpoint = &value
		if err := Validate(record); err != nil {
			t.Fatalf("endpoint=%v must validate: %v", value, err)
		}
	}
}

func TestValidateMptcpTunnelRejectsSRv6(t *testing.T) {
	now := time.Now().UTC()
	record := &Tunnel{
		SchemaVersion: SchemaVersion,
		ID:            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		Generation:    1,
		Name:          "srv6-mptcp",
		Kind:          KindSRv6,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
		Spec: Spec{
			SRv6: &SRv6Spec{
				UnderlayInterface:      "eth0",
				Table:                  200,
				RulePriority:           100,
				RefreshIntervalSeconds: 3600,
				Sources: []SRv6Source{{
					Name:      "default",
					Family:    SRv6FamilyIPv4,
					PrefixURL: "https://example.invalid/routes",
					SID:       netip.MustParseAddr("2001:db8::1"),
					Priority:  101,
					MTU:       1400,
				}},
			},
			Mptcp: &MptcpTunnelConfig{},
		},
	}
	if err := Validate(record); err == nil {
		t.Fatal("SRv6 records with an MPTCP section must be rejected")
	}
	// Without the MPTCP section the same record still validates.
	record.Spec.Mptcp = nil
	if err := Validate(record); err != nil {
		t.Fatalf("SRv6 record without MPTCP section must validate: %v", err)
	}
}

func TestMptcpEndpointFollowsGlobalWhenNil(t *testing.T) {
	// A nil Endpoint means "follow the daemon global"; the model keeps the
	// pointer nil so the backend can make that decision.
	record := newMptcpTunnel()
	record.Spec.Mptcp = &MptcpTunnelConfig{}
	if record.Spec.Mptcp.Endpoint != nil {
		t.Fatal("zero-value MptcpTunnelConfig must have a nil endpoint switch")
	}
}
