/*
Package push implements the 60-second in-memory ring buffer and WS sender goroutine.

Design constraints (architecture §5.2, Task 5):
  - Total memory cap: 5 MB across all streams (cgroup enforces 40 MB hard limit; leave headroom).
  - On disconnect: buffer keeps filling; drops oldest at capacity.
  - On reconnect: replay buffer in timestamp order, then resume real-time.
  - host.metrics: JSON frames (protobuf framing deferred until schema is finalised).
  - host.events, host.alert, agent.heartbeat: JSON.
  - Collectors run on their own goroutine; writes to the ring are non-blocking.
*/
package push

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
)

const (
	defaultCapacity  = 6000    // ~60s × 100 metrics/s; 5 MB budget at ~800B/metric
	maxCapacityBytes = 5 << 20 // 5 MB
)

// Frame is one unit sent over the WebSocket.
type Frame struct {
	Type    string          `json:"type"`
	Stream  string          `json:"stream"`
	Payload json.RawMessage `json:"payload"`
	SentAt  time.Time       `json:"sent_at"`
}

// RingBuffer is a fixed-capacity circular buffer of Metric slices.
// Oldest entries are evicted when capacity is reached.
type RingBuffer struct {
	mu      sync.Mutex
	buf     [][]collectors.Metric
	cap     int
	head    int // next write position
	size    int // current number of entries
	dropped int64
}

// NewRingBuffer creates a ring buffer of the given capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &RingBuffer{
		buf: make([][]collectors.Metric, capacity),
		cap: capacity,
	}
}

// Push adds a batch of metrics. If full, evicts the oldest batch.
// This must be non-blocking.
func (r *RingBuffer) Push(batch []collectors.Metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == r.cap {
		// Evict oldest.
		r.head = (r.head + 1) % r.cap
		r.dropped++
	} else {
		r.size++
	}
	writeIdx := (r.head + r.size - 1) % r.cap
	r.buf[writeIdx] = batch
}

// DrainSince returns all batches with metrics timestamped at or after cutoff,
// in insertion order. Used for replay on reconnect.
func (r *RingBuffer) DrainSince(cutoff time.Time) [][]collectors.Metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [][]collectors.Metric
	for i := 0; i < r.size; i++ {
		idx := (r.head + i) % r.cap
		batch := r.buf[idx]
		if len(batch) > 0 && batch[0].Timestamp.After(cutoff) {
			out = append(out, batch)
		}
	}
	return out
}

// Dropped returns the count of evicted batches since creation.
func (r *RingBuffer) Dropped() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// Len returns the current number of batches in the buffer.
func (r *RingBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Sender drains the ring buffer and sends frames over the WS connection.
type Sender struct {
	ring        *RingBuffer
	sendFn      func([]byte) error
	log         *slog.Logger
	connected   bool
	mu          sync.Mutex
	lastConnect time.Time
	subscribes  map[string]bool // stream subscriptions
}

// NewSender creates a Sender.
func NewSender(ring *RingBuffer, sendFn func([]byte) error, log *slog.Logger) *Sender {
	if log == nil {
		log = slog.Default()
	}
	return &Sender{
		ring:       ring,
		sendFn:     sendFn,
		log:        log,
		subscribes: map[string]bool{"host.metrics": true, "host.events": true},
	}
}

// OnConnect is called when the WS reconnects. Replays buffered samples.
func (s *Sender) OnConnect() {
	s.mu.Lock()
	s.connected = true
	s.lastConnect = time.Now()
	s.mu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	replayed := s.ring.DrainSince(cutoff)

	if s.ring.Dropped() > 0 {
		s.log.Warn("push: data loss on reconnect", "dropped_batches", s.ring.Dropped())
	}

	for _, batch := range replayed {
		s.sendBatch("host.metrics", batch)
	}
	s.log.Info("push: replay complete", "batches", len(replayed))
}

// OnDisconnect is called when the WS disconnects.
func (s *Sender) OnDisconnect() {
	s.mu.Lock()
	s.connected = false
	s.mu.Unlock()
}

// Subscribe enables a stream.
func (s *Sender) Subscribe(stream string) {
	s.mu.Lock()
	s.subscribes[stream] = true
	s.mu.Unlock()
}

// Unsubscribe disables a stream.
func (s *Sender) Unsubscribe(stream string) {
	s.mu.Lock()
	delete(s.subscribes, stream)
	s.mu.Unlock()
}

// IsSubscribed returns true if stream is active.
func (s *Sender) IsSubscribed(stream string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribes[stream]
}

// Run drains the input channel and sends to WS when connected.
func (s *Sender) Run(ctx context.Context, metricsCh <-chan []collectors.Metric) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-metricsCh:
			if !ok {
				return
			}
			// Always push to ring (even if disconnected — buffered for replay).
			s.ring.Push(batch)

			s.mu.Lock()
			connected := s.connected
			subscribed := s.subscribes["host.metrics"]
			s.mu.Unlock()

			if connected && subscribed {
				s.sendBatch("host.metrics", batch)
			}
		}
	}
}

// SendAlert sends a host.alert or host.alert.cleared frame immediately.
func (s *Sender) SendAlert(payload json.RawMessage, cleared bool) {
	stream := "host.alert"
	if cleared {
		stream = "host.alert.cleared"
	}
	s.sendFrame(stream, payload)
}

// SendHeartbeat sends an agent.heartbeat frame.
func (s *Sender) SendHeartbeat(payload json.RawMessage) {
	s.sendFrame("agent.heartbeat", payload)
}

func (s *Sender) sendBatch(stream string, batch []collectors.Metric) {
	payload, err := json.Marshal(batch)
	if err != nil {
		return
	}
	s.sendFrame(stream, payload)
}

func (s *Sender) sendFrame(stream string, payload json.RawMessage) {
	frame := Frame{
		Type:    "push",
		Stream:  stream,
		Payload: payload,
		SentAt:  time.Now(),
	}
	data, err := json.Marshal(frame)
	if err != nil {
		return
	}
	if err := s.sendFn(data); err != nil {
		s.log.Warn("push: send error", "stream", stream, "err", err)
	}
}
