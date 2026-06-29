package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

type replayStore struct {
	path string
	file *os.File
	ttl  time.Duration
	seen map[string]time.Time
}

type replayRecord struct {
	JobID      string    `json:"job_id"`
	ObservedAt time.Time `json:"observed_at"`
}

func openReplayStore(path string, ttl time.Duration) (*replayStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("replay store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("replay store mkdir: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("replay store open %q: %w", path, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("replay store lock: %w", err)
	}
	store := &replayStore{path: path, file: file, ttl: ttl, seen: map[string]time.Time{}}
	if err := store.load(); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.rewriteActive(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *replayStore) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	_ = syscall.Flock(int(s.file.Fd()), syscall.LOCK_UN)
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *replayStore) Seen(jobID string) bool {
	observed, ok := s.seen[strings.TrimSpace(jobID)]
	return ok && time.Since(observed) < s.ttl
}

func (s *replayStore) Remember(jobID string) error {
	trimmed := strings.TrimSpace(jobID)
	if trimmed == "" {
		return fmt.Errorf("replay store job id is required")
	}
	record := replayRecord{JobID: trimmed, ObservedAt: time.Now().UTC()}
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("replay store marshal: %w", err)
	}
	if _, err := s.file.Seek(0, os.SEEK_END); err != nil {
		return fmt.Errorf("replay store seek: %w", err)
	}
	if _, err := s.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("replay store write: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("replay store sync: %w", err)
	}
	s.seen[trimmed] = record.ObservedAt
	return nil
}

func (s *replayStore) ReplayCache() *envpkg.ReplayCache {
	cache := envpkg.NewReplayCache(len(s.seen)+1, s.ttl)
	for jobID := range s.seen {
		cache.Remember(jobID)
	}
	return cache
}

func (s *replayStore) load() error {
	if _, err := s.file.Seek(0, 0); err != nil {
		return fmt.Errorf("replay store seek start: %w", err)
	}
	scanner := bufio.NewScanner(s.file)
	cutoff := time.Now().Add(-s.ttl)
	for scanner.Scan() {
		var record replayRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		if strings.TrimSpace(record.JobID) == "" || record.ObservedAt.Before(cutoff) {
			continue
		}
		s.seen[record.JobID] = record.ObservedAt
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("replay store scan: %w", err)
	}
	return nil
}

func (s *replayStore) rewriteActive() error {
	if err := s.file.Truncate(0); err != nil {
		return fmt.Errorf("replay store truncate: %w", err)
	}
	if _, err := s.file.Seek(0, 0); err != nil {
		return fmt.Errorf("replay store rewind: %w", err)
	}
	for jobID, observedAt := range s.seen {
		line, err := json.Marshal(replayRecord{JobID: jobID, ObservedAt: observedAt})
		if err != nil {
			return fmt.Errorf("replay store marshal active: %w", err)
		}
		if _, err := s.file.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("replay store rewrite: %w", err)
		}
	}
	return s.file.Sync()
}
