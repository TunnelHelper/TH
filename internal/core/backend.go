package core

import (
	"context"

	"github.com/sudogeeker/tunnel-helper/internal/model"
)

type Observation struct {
	InterfaceExists bool
	InterfaceUp     bool
	Details         map[string]string
}

type BackendHealth struct {
	Available bool   `json:"available"`
	Message   string `json:"message,omitempty"`
}

type Backend interface {
	Apply(context.Context, model.Tunnel) (Observation, error)
	Remove(context.Context, model.Tunnel) (Observation, error)
	Observe(context.Context, model.Tunnel) (Observation, error)
	Health(context.Context) map[model.Kind]BackendHealth
	Events() <-chan struct{}
	Close() error
}

type Store interface {
	List() ([]model.Tunnel, error)
	Get(string) (model.Tunnel, error)
	Create(model.Tunnel) error
	Update(model.Tunnel, uint64) error
	Delete(string, uint64) error
}
