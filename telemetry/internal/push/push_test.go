package push_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
	"github.com/pmx-cloud/agents/telemetry/internal/push"
)

func makeBatch(n int) []collectors.Metric {
	batch := make([]collectors.Metric, n)
	for i := range batch {
		batch[i] = collectors.Metric{
			Name:      "host_load1",
			Value:     float64(i),
			Timestamp: time.Now(),
		}
	}
	return batch
}

func TestRingBuffer_PushAndLen(t *testing.T) {
	r := push.NewRingBuffer(100)
	r.Push(makeBatch(5))
	r.Push(makeBatch(3))
	if r.Len() != 2 {
		t.Fatalf("expected 2 batches, got %d", r.Len())
	}
}

func TestRingBuffer_EvictsOldestAtCapacity(t *testing.T) {
	r := push.NewRingBuffer(3)
	r.Push(makeBatch(1))
	r.Push(makeBatch(1))
	r.Push(makeBatch(1))
	r.Push(makeBatch(1)) // evicts first

	if r.Dropped() != 1 {
		t.Fatalf("expected 1 dropped, got %d", r.Dropped())
	}
	if r.Len() != 3 {
		t.Fatalf("expected 3 after eviction, got %d", r.Len())
	}
}

func TestRingBuffer_DrainSince_ReturnsRecent(t *testing.T) {
	r := push.NewRingBuffer(100)
	old := []collectors.Metric{{Name: "m", Value: 1, Timestamp: time.Now().Add(-120 * time.Second)}}
	r.Push(old)
	recent := []collectors.Metric{{Name: "m", Value: 2, Timestamp: time.Now()}}
	r.Push(recent)
	cutoff := time.Now().Add(-60 * time.Second)
	batches := r.DrainSince(cutoff)
	if len(batches) != 1 {
		t.Fatalf("expected 1 recent batch, got %d", len(batches))
	}
	if batches[0][0].Value != 2 {
		t.Fatalf("wrong batch returned")
	}
}

func TestRingBuffer_DrainSince_AllWithinWindow(t *testing.T) {
	r := push.NewRingBuffer(100)
	for i := 0; i < 30; i++ {
		r.Push([]collectors.Metric{{
			Name:      "m",
			Value:     float64(i),
			Timestamp: time.Now().Add(-time.Duration(30-i) * time.Second),
		}})
	}
	cutoff := time.Now().Add(-60 * time.Second)
	batches := r.DrainSince(cutoff)
	if len(batches) != 30 {
		t.Fatalf("expected 30 batches within 60s window, got %d", len(batches))
	}
}

func TestSender_SubscribeUnsubscribe(t *testing.T) {
	r := push.NewRingBuffer(100)
	s := push.NewSender(r, func([]byte) error { return nil }, nil)

	if !s.IsSubscribed("host.metrics") {
		t.Fatal("host.metrics should be subscribed by default")
	}
	s.Unsubscribe("host.metrics")
	if s.IsSubscribed("host.metrics") {
		t.Fatal("should be unsubscribed")
	}
	s.Subscribe("host.metrics")
	if !s.IsSubscribed("host.metrics") {
		t.Fatal("should be re-subscribed")
	}
}

func TestSender_OnConnect_ReplayBuffer(t *testing.T) {
	r := push.NewRingBuffer(100)
	r.Push([]collectors.Metric{{Name: "m", Value: 1, Timestamp: time.Now()}})

	var sent [][]byte
	var mu sync.Mutex
	s := push.NewSender(r, func(data []byte) error {
		mu.Lock()
		sent = append(sent, data)
		mu.Unlock()
		return nil
	}, nil)

	s.OnConnect()
	mu.Lock()
	n := len(sent)
	mu.Unlock()
	if n == 0 {
		t.Fatal("expected replayed frames on connect")
	}
}

func TestSender_OnDisconnect_DoesNotPanic(t *testing.T) {
	r := push.NewRingBuffer(100)
	s := push.NewSender(r, func([]byte) error { return nil }, nil)
	s.OnDisconnect()
}

func TestSender_Run_PushesToRing(t *testing.T) {
	r := push.NewRingBuffer(100)
	s := push.NewSender(r, func([]byte) error { return nil }, nil)
	s.OnConnect()

	ch := make(chan []collectors.Metric, 1)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Run(ctx, ch)
	}()

	ch <- makeBatch(3)
	time.Sleep(20 * time.Millisecond)
	cancel()
	wg.Wait()

	if r.Len() == 0 {
		t.Fatal("expected batch pushed to ring")
	}
}

func TestSender_SendAlert(t *testing.T) {
	r := push.NewRingBuffer(100)
	var sent [][]byte
	var mu sync.Mutex
	s := push.NewSender(r, func(data []byte) error {
		mu.Lock()
		sent = append(sent, data)
		mu.Unlock()
		return nil
	}, nil)
	s.OnConnect()
	s.SendAlert([]byte(`{"id":"t1"}`), false)
	s.SendAlert([]byte(`{"id":"t1"}`), true)

	mu.Lock()
	n := len(sent)
	mu.Unlock()
	if n < 2 {
		t.Fatalf("expected 2 alert frames (fire + cleared), got %d", n)
	}
}

func TestRingBuffer_DefaultCapacity(t *testing.T) {
	r := push.NewRingBuffer(0) // 0 = use default
	r.Push(makeBatch(1))
	if r.Len() != 1 {
		t.Fatal("default capacity ring should accept pushes")
	}
}
