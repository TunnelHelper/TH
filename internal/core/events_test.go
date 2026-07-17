package core

import (
	"math"
	"testing"
)

func TestEventHubReplayGapAndLiveDelivery(t *testing.T) {
	hub := NewEventHub(2)
	hub.Publish(Event{Type: EventStatus, TunnelID: "one"})
	hub.Publish(Event{Type: EventStatus, TunnelID: "two"})
	hub.Publish(Event{Type: EventStatus, TunnelID: "three"})

	subscription := hub.Subscribe(1)
	defer subscription.Cancel()
	if subscription.Current != 3 || subscription.Oldest != 2 || len(subscription.Replay) != 2 {
		t.Fatalf("subscription = %+v", subscription)
	}
	if subscription.Gap {
		t.Fatal("contiguous replay was marked as a gap")
	}
	hub.Publish(Event{Type: EventDeleted, TunnelID: "four"})
	select {
	case event := <-subscription.Events:
		if event.Sequence != 4 || event.TunnelID != "four" {
			t.Fatalf("live event = %+v", event)
		}
	default:
		t.Fatal("live event was not delivered")
	}

	gap := hub.Subscribe(1)
	defer gap.Cancel()
	if !gap.Gap || gap.Oldest != 3 {
		t.Fatalf("gap subscription = %+v", gap)
	}
}

func TestEventHubDisconnectsSlowSubscriberForReplay(t *testing.T) {
	hub := NewEventHub(128)
	subscription := hub.Subscribe(0)
	defer subscription.Cancel()

	for sequence := 1; sequence <= 65; sequence++ {
		hub.Publish(Event{Type: EventStatus, TunnelID: "busy"})
	}
	received := uint64(0)
	for event := range subscription.Events {
		received = event.Sequence
	}
	if received != 64 {
		t.Fatalf("last buffered sequence = %d, want 64", received)
	}

	reconnected := hub.Subscribe(received)
	defer reconnected.Cancel()
	if reconnected.Gap || len(reconnected.Replay) != 1 || reconnected.Replay[0].Sequence != 65 {
		t.Fatalf("reconnected subscription = %+v", reconnected)
	}
}

func TestEventHubFutureSequenceDoesNotOverflowGapCheck(t *testing.T) {
	hub := NewEventHub(1)
	hub.Publish(Event{Type: EventStatus})
	subscription := hub.Subscribe(math.MaxUint64)
	defer subscription.Cancel()
	if subscription.Gap {
		t.Fatalf("future sequence was marked as a history gap: %+v", subscription)
	}
}
