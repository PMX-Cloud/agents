package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestClassifyReject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		errMsg string
		want   string
	}{
		{"bad signature: invalid", "BAD_SIGNATURE"},
		{"audience mismatch: expected x", "AUDIENCE_MISMATCH"},
		{"expired at now", "EXPIRED"},
		{"replay detected", "REPLAY"},
		{"other", "VERIFY_FAILED"},
	}
	for _, tc := range cases {
		got := classifyReject(assertErr(tc.errMsg))
		if got != tc.want {
			t.Fatalf("classifyReject(%q) = %q, want %q", tc.errMsg, got, tc.want)
		}
	}
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

func assertErr(msg string) error { return simpleErr(msg) }

func TestReplayStorePersistsSeenJobIDs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "replay.log")
	store, err := openReplayStore(path, 2*time.Hour)
	if err != nil {
		t.Fatalf("openReplayStore() error = %v", err)
	}
	defer store.Close()
	if store.Seen("job-1") {
		t.Fatal("job should not be seen before append")
	}
	if err := store.Remember("job-1"); err != nil {
		t.Fatalf("Remember() error = %v", err)
	}
	if !store.Seen("job-1") {
		t.Fatal("job should be seen after append")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := openReplayStore(path, 2*time.Hour)
	if err != nil {
		t.Fatalf("reopen replay store: %v", err)
	}
	defer reopened.Close()
	if !reopened.Seen("job-1") {
		t.Fatal("job should be seen after reopening store")
	}
}
