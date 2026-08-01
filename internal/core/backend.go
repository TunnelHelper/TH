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
