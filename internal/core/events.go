package core

import (
	"sync"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
)

type EventType string

const (
	EventConnected EventType = "connected"
	EventHeartbeat EventType = "heartbeat"
	EventStatus    EventType = "status"
	EventDeleted   EventType = "deleted"
)

type Event struct {
	Sequence   uint64            `json:"sequence"`
	Time       time.Time         `json:"time"`
	Type       EventType         `json:"type"`
	TunnelID   string            `json:"tunnel_id,omitempty"`
	TunnelName string            `json:"tunnel_name,omitempty"`
	TunnelKind model.Kind        `json:"tunnel_kind,omitempty"`
	Enabled    bool              `json:"enabled,omitempty"`
	Generation uint64            `json:"generation,omitempty"`
	Phase      model.Phase       `json:"phase,omitempty"`
	Message    string            `json:"message,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Status     *model.Status     `json:"status,omitempty"`
}

type EventSubscription struct {
	Replay  []Event
	Events  <-chan Event
	Current uint64
	Oldest  uint64
	Gap     bool
	Cancel  func()
}

type EventHub struct {
	mu          sync.Mutex
	next        uint64
	capacity    int
	history     []Event
	subscribers map[uint64]chan Event
	nextSub     uint64
}

func NewEventHub(capacity int) *EventHub {
	if capacity < 1 {
		capacity = 1
	}
	return &EventHub{capacity: capacity, subscribers: make(map[uint64]chan Event)}
}

func (h *EventHub) Publish(event Event) Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	event.Sequence = h.next
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	historyEvent := event
	// Replayed events are change notifications, not state snapshots. Keeping
	// peer telemetry for every reconcile would retain unbounded history data.
	historyEvent.Status = nil
	h.history = append(h.history, historyEvent)
	if len(h.history) > h.capacity {
		copy(h.history, h.history[len(h.history)-h.capacity:])
		h.history = h.history[:h.capacity]
	}
	for _, subscriber := range h.subscribers {
		select {
		case subscriber <- event:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- event:
			default:
			}
		}
	}
	return event
}

func (h *EventHub) Subscribe(after uint64) EventSubscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextSub++
	id := h.nextSub
	stream := make(chan Event, 64)
	h.subscribers[id] = stream
	oldest := h.next + 1
	if len(h.history) != 0 {
		oldest = h.history[0].Sequence
	}
	replay := make([]Event, 0, len(h.history))
	for _, event := range h.history {
		if event.Sequence > after {
			replay = append(replay, event)
		}
	}
	var once sync.Once
	return EventSubscription{
		Replay:  replay,
		Events:  stream,
		Current: h.next,
		Oldest:  oldest,
		Gap:     after != 0 && after+1 < oldest,
		Cancel: func() {
			once.Do(func() {
				h.mu.Lock()
				delete(h.subscribers, id)
				h.mu.Unlock()
			})
		},
	}
}
