package core

import (
	"context"
	"errors"

	"github.com/TunnelHelper/TH/internal/model"
)

var ErrDriftDetected = errors.New("managed state drift detected")

type Observation struct {
	InterfaceExists bool
	InterfaceUp     bool
	Details         map[string]string
	Peers           []model.PeerStatus
}

type BackendHealth struct {
	Available bool   `json:"available"`
	Required  bool   `json:"required"`
	Message   string `json:"message,omitempty"`
}

// MptcpHealth reports the daemon-wide MPTCP infrastructure state: whether
// the kernel supports it, whether TH endpoint management is enabled, and
// how many TH-managed endpoints are currently registered.
type MptcpHealth struct {
	Supported bool   `json:"supported"`
	Enabled   bool   `json:"enabled"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Endpoints int    `json:"endpoints"`
}

// BabelHealth reports the daemon-wide Babel state. RouterID is the
// identifier the running speaker actually uses: the configured value, or
// the persisted auto-generated one when the configuration leaves it empty.
type BabelHealth struct {
	RouterID           string                 `json:"router_id,omitempty"`
	OriginatedPrefixes []string               `json:"originated_prefixes,omitempty"`
	Neighbours         []BabelNeighbourHealth `json:"neighbours,omitempty"`
	Routes             []BabelRouteHealth     `json:"routes,omitempty"`
}

type BabelNeighbourHealth struct {
	Interface    string  `json:"interface"`
	Address      string  `json:"address"`
	RTTMicros    int64   `json:"rtt_micros"`
	JitterMicros int64   `json:"jitter_micros"`
	MinRTTMicros int64   `json:"min_rtt_micros"`
	AgeMillis    int64   `json:"age_millis"`
	Samples      uint32  `json:"samples"`
	Outliers     uint32  `json:"outliers"`
	Confidence   float64 `json:"confidence"`
	Fresh        bool    `json:"fresh"`
}

type BabelRouteHealth struct {
	Prefix          string  `json:"prefix"`
	Interface       string  `json:"interface"`
	NextHop         string  `json:"next_hop"`
	PreferredSource string  `json:"preferred_source,omitempty"`
	Metric          uint16  `json:"metric"`
	BottleneckMbps  int     `json:"bottleneck_mbps"`
	RTTMicros       int64   `json:"rtt_micros"`
	JitterMicros    int64   `json:"jitter_micros"`
	AgeMillis       int64   `json:"age_millis"`
	Confidence      float64 `json:"confidence"`
	Score           float64 `json:"score"`
	DesiredWeight   int     `json:"desired_weight"`
	InstalledWeight int     `json:"installed_weight,omitempty"`
}

type BackendEventType string

const (
	BackendEventLink    BackendEventType = "link"
	BackendEventAddress BackendEventType = "address"
	BackendEventRoute   BackendEventType = "route"
	BackendEventXFRM    BackendEventType = "xfrm"
	BackendEventVICI    BackendEventType = "vici"
)

type BackendEvent struct {
	Type       BackendEventType
	RecordID   string
	Interface  string
	RouteTable int
	XFRMIfID   uint32
}

type Backend interface {
	Apply(context.Context, model.Tunnel) (Observation, error)
	Remove(context.Context, model.Tunnel) (Observation, error)
	Observe(context.Context, model.Tunnel) (Observation, error)
	Health(context.Context) map[model.Kind]BackendHealth
	// ReconcileGlobal reconciles daemon-global state (currently the MPTCP
	// endpoint set) from the authoritative record list. It runs at daemon
	// startup and on the periodic reconcile pass.
	ReconcileGlobal(context.Context, []model.Tunnel) error
	MptcpHealth() MptcpHealth
	BabelHealth() BabelHealth
	Events() <-chan BackendEvent
	Close() error
}

type Store interface {
	List() ([]model.Tunnel, error)
	Get(string) (model.Tunnel, error)
	Create(model.Tunnel) error
	Update(model.Tunnel, uint64) error
	Delete(string, uint64) error
}
