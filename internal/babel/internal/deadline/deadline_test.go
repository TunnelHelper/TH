// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package deadline_test

import (
	"sync"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/internal/deadline"
)

func eventuallyReceive(t *testing.T, d *deadline.Deadline) {
	t.Helper()
	select {
	case <-d.C:
	case <-time.After(time.Second):
		t.Fatal("deadline did not fire")
	}
}

func consistentlyNoReceive(t *testing.T, d *deadline.Deadline, duration time.Duration) {
	t.Helper()
	select {
	case <-d.C:
		t.Fatal("deadline fired unexpectedly")
	case <-time.After(duration):
	}
}

func TestDeadlineChannelNotNil(t *testing.T) {
	d := deadline.NewDeadline()
	if d.C == nil {
		t.Fatal("channel must not be nil")
	}
}

func TestDeadlineStopWhenNotArmed(t *testing.T) {
	d := deadline.NewDeadline()
	d.Stop()
	if d.Expired() {
		t.Fatal("must not be expired")
	}
}

func TestDeadlineStopWhenArmed(t *testing.T) {
	d := deadline.NewDeadline()
	d.Reset(10 * time.Millisecond)
	d.Stop()
	consistentlyNoReceive(t, &d, 30*time.Millisecond)
	if d.Expired() {
		t.Fatal("must not be expired")
	}
}

func TestDeadlineDoesNotExpireWhenNotSet(t *testing.T) {
	d := deadline.NewDeadline()
	consistentlyNoReceive(t, &d, 20*time.Millisecond)
	if d.Expired() {
		t.Fatal("must not be expired")
	}
}

func TestDeadlineExpiresWhenSet(t *testing.T) {
	d := deadline.NewDeadline()
	d.Reset(10 * time.Millisecond)
	eventuallyReceive(t, &d)
	if !d.Expired() {
		t.Fatal("must be expired")
	}
}

func TestDeadlineCanBeRearmed(t *testing.T) {
	d := deadline.NewDeadline()
	d.Reset(10 * time.Millisecond)
	eventuallyReceive(t, &d)
	if !d.Expired() {
		t.Fatal("must be expired")
	}

	d.Reset(10 * time.Millisecond)
	if d.Expired() {
		t.Fatal("re-armed deadline must not be expired")
	}
	eventuallyReceive(t, &d)
	if !d.Expired() {
		t.Fatal("must be expired after re-arm")
	}
}

func TestDeadlineCanBeResetWhileArmed(t *testing.T) {
	d := deadline.NewDeadline()
	started := time.Now()
	d.Reset(10 * time.Millisecond)
	d.Reset(100 * time.Millisecond)
	eventuallyReceive(t, &d)
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("reset must extend the deadline, fired after %v", elapsed)
	}
}

func TestDeadlineCanBeResetTwiceWhileArmed(t *testing.T) {
	d := deadline.NewDeadline()
	started := time.Now()
	d.Reset(10 * time.Millisecond)
	d.Reset(100 * time.Millisecond)
	d.Reset(10 * time.Millisecond)
	eventuallyReceive(t, &d)
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > 50*time.Millisecond {
		t.Fatalf("second reset must shorten the deadline, fired after %v", elapsed)
	}
}

func TestDeadlineConcurrentResetAndStop(t *testing.T) {
	d := deadline.NewDeadline()
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				d.Reset(time.Millisecond)
				d.Stop()
			}
		}()
	}
	workers.Wait()
	d.Reset(time.Millisecond)
	eventuallyReceive(t, &d)
}
