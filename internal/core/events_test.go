package core

import "testing"

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
