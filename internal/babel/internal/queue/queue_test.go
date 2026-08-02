// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package queue_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/babel/internal/queue"
	"github.com/TunnelHelper/TH/internal/babel/proto"
)

type captureWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *captureWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *captureWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

func TestQueueSendsValue(t *testing.T) {
	writer := &captureWriter{}
	q := queue.NewQueue(1500, writer)
	defer func() {
		if err := q.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	q.SendValue(&proto.Hello{Seqno: 1, Interval: time.Second}, 5*time.Millisecond)

	deadline := time.After(2 * time.Second)
	for writer.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("queue never sent the value")
		case <-time.After(5 * time.Millisecond):
		}
	}

	writer.mu.Lock()
	packet := writer.buf.Bytes()
	writer.mu.Unlock()
	if len(packet) < 4 || packet[0] != proto.PacketHeaderMagic {
		t.Fatalf("unexpected packet bytes: %x", packet)
	}
}

func TestQueueStampsHelloAtTransmitTime(t *testing.T) {
	writer := &captureWriter{}
	q := queue.NewQueue(1500, writer)
	defer func() {
		if err := q.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	hello := &proto.Hello{
		Seqno: 1, Interval: time.Second,
		Timestamp: &proto.TimestampHello{Transmit: 1},
	}
	q.SendValue(hello, 20*time.Millisecond)

	deadline := time.After(2 * time.Second)
	for writer.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("queue never sent the timestamped Hello")
		case <-time.After(time.Millisecond):
		}
	}

	writer.mu.Lock()
	packetBytes := append([]byte(nil), writer.buf.Bytes()...)
	writer.mu.Unlock()
	_, packet, err := proto.NewParser().Packet(packetBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := packet.Body[0].(*proto.Hello)
	if !ok || got.Timestamp == nil {
		t.Fatalf("packet does not contain a timestamped Hello: %+v", packet.Body)
	}
	if got.Timestamp.Transmit == 1 {
		t.Fatal("Hello retained its enqueue timestamp")
	}
}
