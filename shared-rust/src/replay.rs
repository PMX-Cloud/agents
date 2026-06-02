//! Replay-protection ring buffer — mirrors agents/shared/envelope/replay.go.

use indexmap::IndexMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A goroutine-safe, fixed-capacity ring buffer of seen job IDs.
///
/// Uses `IndexMap` for insertion-ordered O(1) eviction of the oldest entry
/// and `parking_lot::RwLock` for low-contention reads.
#[derive(Clone)]
pub struct ReplayCache {
    inner: Arc<RwLock<Inner>>,
}

struct Inner {
    capacity: usize,
    ttl: Duration,
    map: IndexMap<String, Instant>, // job_id → observed_at
}

impl ReplayCache {
    /// Create a new replay cache with given capacity and TTL.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                capacity,
                ttl,
                map: IndexMap::with_capacity(capacity),
            })),
        }
    }

    /// Returns `true` if `job_id` has been seen within the TTL window.
    pub fn seen(&self, job_id: &str) -> bool {
        let inner = self.inner.read();
        match inner.map.get(job_id) {
            Some(observed_at) => observed_at.elapsed() < inner.ttl,
            None => false,
        }
    }

    /// Records `job_id` as seen. Evicts the oldest entry if at capacity.
    pub fn remember(&mut self, job_id: String) {
        let mut inner = self.inner.write();
        if inner.map.contains_key(&job_id) {
            // Update timestamp — move to end (most recent).
            inner.map.swap_remove(&job_id);
        } else if inner.map.len() >= inner.capacity {
            // Evict the oldest (first) entry.
            inner.map.shift_remove_index(0);
        }
        inner.map.insert(job_id, Instant::now());
    }

    /// Remove entries older than TTL. Call periodically from a background task.
    pub fn purge(&self) {
        let mut inner = self.inner.write();
        let ttl = inner.ttl;
        inner
            .map
            .retain(|_, observed_at| observed_at.elapsed() < ttl);
    }

    /// Returns the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.inner.read().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_after_remember() {
        let mut cache = ReplayCache::new(10, Duration::from_secs(60));
        assert!(!cache.seen("job-1"));
        cache.remember("job-1".to_string());
        assert!(cache.seen("job-1"));
    }

    #[test]
    fn test_evict_oldest_at_capacity() {
        let mut cache = ReplayCache::new(3, Duration::from_secs(60));
        cache.remember("job-1".to_string());
        cache.remember("job-2".to_string());
        cache.remember("job-3".to_string());
        // Adding a 4th should evict job-1.
        cache.remember("job-4".to_string());
        assert!(!cache.seen("job-1"), "job-1 should have been evicted");
        assert!(cache.seen("job-4"));
    }

    #[test]
    fn test_replay_detection() {
        let mut cache = ReplayCache::new(10, Duration::from_secs(60));
        cache.remember("job-x".to_string());
        assert!(cache.seen("job-x"), "should be detected as replay");
    }
}
