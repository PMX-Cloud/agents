package envelope

import (
	"container/list"
	"sync"
	"time"
)

// replayEntry holds a jobID and the time it was observed.
type replayEntry struct {
	jobID      string
	observedAt time.Time
}

// ReplayCache is a 24-hour, fixed-size, goroutine-safe ring buffer of seen
// jobIds. It rejects duplicates (architecture §3.4 — replay protection).
//
// Implementation: a hash map for O(1) lookup + a doubly-linked list for
// ordered eviction (oldest-first). RSS target: ≤ 10 MB for 8.64M entries.
type ReplayCache struct {
	mu       sync.RWMutex
	capacity int
	ttl      time.Duration
	index    map[string]*list.Element // jobID → list element
	order    *list.List               // front = oldest
	stopCh   chan struct{}
}

// NewReplayCache creates a replay cache with the given capacity and TTL.
// A background goroutine purges expired entries every minute.
// Call Close() when done (e.g. in tests) to stop the goroutine.
func NewReplayCache(capacity int, ttl time.Duration) *ReplayCache {
	c := &ReplayCache{
		capacity: capacity,
		ttl:      ttl,
		index:    make(map[string]*list.Element, capacity),
		order:    list.New(),
		stopCh:   make(chan struct{}),
	}
	go c.purgeLoop()
	return c
}

// Seen returns true if jobID has been seen within the TTL window.
func (c *ReplayCache) Seen(jobID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	el, ok := c.index[jobID]
	if !ok {
		return false
	}
	entry := el.Value.(*replayEntry)
	return time.Since(entry.observedAt) < c.ttl
}

// Remember records jobID as seen. If the cache is at capacity, the oldest
// entry is evicted to make room (oldest = lowest insertion order, regardless
// of TTL). This matches the spec: evict oldest, not newest.
func (c *ReplayCache) Remember(jobID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Already in cache — update timestamp and move to back (most recent).
	if el, ok := c.index[jobID]; ok {
		el.Value.(*replayEntry).observedAt = time.Now()
		c.order.MoveToBack(el)
		return
	}

	// Evict oldest if at capacity.
	if c.order.Len() >= c.capacity {
		oldest := c.order.Front()
		if oldest != nil {
			entry := oldest.Value.(*replayEntry)
			delete(c.index, entry.jobID)
			c.order.Remove(oldest)
		}
	}

	// Insert new entry at the back (most recent).
	el := c.order.PushBack(&replayEntry{
		jobID:      jobID,
		observedAt: time.Now(),
	})
	c.index[jobID] = el
}

// Close stops the background purge goroutine. Safe to call multiple times.
func (c *ReplayCache) Close() {
	select {
	case <-c.stopCh:
		// already closed
	default:
		close(c.stopCh)
	}
}

// Len returns the current number of entries (for testing).
func (c *ReplayCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// purgeLoop runs in the background and removes entries older than TTL every
// minute. It walks the list from front (oldest) until it hits a non-expired
// entry, then stops — no need to traverse further because entries are in
// insertion order.
func (c *ReplayCache) purgeLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.purge()
		}
	}
}

func (c *ReplayCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.ttl)
	for {
		front := c.order.Front()
		if front == nil {
			break
		}
		entry := front.Value.(*replayEntry)
		if entry.observedAt.After(cutoff) {
			break // rest of list is newer
		}
		delete(c.index, entry.jobID)
		c.order.Remove(front)
	}
}
