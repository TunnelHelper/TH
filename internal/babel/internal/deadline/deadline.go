// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package deadline

import (
	"sync"
	"sync/atomic"
	"time"
)

type Deadline struct {
	C chan any

	expired atomic.Bool

	mu         sync.Mutex
	timer      *time.Timer
	generation uint64
	closed     bool
}

func NewDeadline() Deadline {
	return Deadline{
		// Buffered so a timer that fires while no receiver is ready does
		// not block the AfterFunc goroutine forever.
		C: make(chan any, 1),
	}
}

func (t *Deadline) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.generation++
	t.stopLocked()
	close(t.C)
	return nil
}

func (t *Deadline) Expired() bool {
	return t.expired.Load()
}

func (t *Deadline) Reset(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.expired.Store(false)
	t.generation++
	generation := t.generation
	t.stopLocked()
	t.timer = time.AfterFunc(d, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.closed || t.generation != generation {
			return
		}
		t.expired.Store(true)
		select {
		case t.C <- nil:
		default:
		}
	})
}

func (t *Deadline) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.generation++
	t.stopLocked()
}

func (t *Deadline) stopLocked() {
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}
