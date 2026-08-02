// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package deadline

import (
	"sync/atomic"
	"time"
)

type Deadline struct {
	C chan any

	expired atomic.Bool
	timer   *time.Timer
}

func NewDeadline() Deadline {
	return Deadline{
		// Buffered so a timer that fires while no receiver is ready does
		// not block the AfterFunc goroutine forever.
		C: make(chan any, 1),
	}
}

func (t *Deadline) Close() error {
	close(t.C)
	return nil
}

func (t *Deadline) Expired() bool {
	return t.expired.Load()
}

func (t *Deadline) Reset(d time.Duration) {
	t.expired.Store(false)

	t.Stop()
	t.timer = time.AfterFunc(d, func() {
		t.expired.Store(true)
		select {
		case t.C <- nil:
		default:
		}
	})
}

func (t *Deadline) Stop() {
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}
