package envelope

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// keyEntry is one Ed25519 public key with an optional expiry (not-after).
type keyEntry struct {
	pub      ed25519.PublicKey
	notAfter time.Time // zero value means no expiry
}

// isActive returns true if the key has not yet expired.
func (k *keyEntry) isActive() bool {
	if k.notAfter.IsZero() {
		return true
	}
	return time.Now().Before(k.notAfter)
}

// KeySet holds a set of Ed25519 public keys used to verify envelope signatures.
// Multiple keys are supported so the backend can rotate: new key is added,
// agents update, then old key is removed after a 30-day overlap (architecture §3.4).
type KeySet struct {
	mu      sync.RWMutex
	entries []keyEntry
}

// LoadKeySet reads the keyset file at path.
//
// File format (one entry per line, lines starting with '#' are comments):
//
//	<hex-encoded 32-byte Ed25519 pubkey> [<RFC-3339 not-after>]
//
// Example:
//
//	3d4e5a... 2026-08-01T00:00:00Z
//	1f2a3b... # current, no expiry
func LoadKeySet(path string) (*KeySet, error) {
	f, err := os.Open(path) // #nosec G304 -- keyset path is operator-configured, not attacker-controlled
	if err != nil {
		return nil, fmt.Errorf("keyset: open %q: %w", path, err)
	}
	defer f.Close()

	ks := &KeySet{}
	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		// strip inline comments
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = strings.TrimSpace(raw[:idx])
		}
		if raw == "" {
			continue
		}

		parts := strings.Fields(raw)
		if len(parts) < 1 || len(parts) > 2 {
			return nil, fmt.Errorf("keyset: line %d: expected 1 or 2 fields, got %d", line, len(parts))
		}

		pubBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("keyset: line %d: invalid hex: %w", line, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyset: line %d: key must be %d bytes, got %d", line, ed25519.PublicKeySize, len(pubBytes))
		}

		entry := keyEntry{pub: ed25519.PublicKey(pubBytes)}

		if len(parts) == 2 {
			t, err := time.Parse(time.RFC3339, parts[1])
			if err != nil {
				return nil, fmt.Errorf("keyset: line %d: invalid not-after timestamp %q: %w", line, parts[1], err)
			}
			entry.notAfter = t
		}

		ks.entries = append(ks.entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("keyset: scan %q: %w", path, err)
	}
	if len(ks.entries) == 0 {
		return nil, fmt.Errorf("keyset: %q contains no keys", path)
	}
	return ks, nil
}

// Verify returns true if signature is a valid Ed25519 signature over message
// using at least one non-expired key in the set. Expired keys are skipped.
func (k *KeySet) Verify(message, signature []byte) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, entry := range k.entries {
		if !entry.isActive() {
			continue
		}
		if ed25519.Verify(entry.pub, message, signature) {
			return true
		}
	}
	return false
}

// Update atomically replaces the keyset. Keys whose not-after is in the past
// are dropped from the new set.
func (k *KeySet) Update(newSet *KeySet) error {
	if newSet == nil {
		return fmt.Errorf("keyset: Update called with nil set")
	}
	newSet.mu.RLock()
	active := make([]keyEntry, 0, len(newSet.entries))
	for _, e := range newSet.entries {
		if e.isActive() {
			active = append(active, e)
		}
	}
	newSet.mu.RUnlock()

	if len(active) == 0 {
		return fmt.Errorf("keyset: update would leave no active keys")
	}

	k.mu.Lock()
	k.entries = active
	k.mu.Unlock()
	return nil
}

// Len returns the total number of keys (active or expired) in the set.
func (k *KeySet) Len() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.entries)
}

// ParseKeySet parses a keyset from a multiline string (same format as LoadKeySet).
// Primarily useful in tests without touching the filesystem.
func ParseKeySet(content string) (*KeySet, error) {
	ks := &KeySet{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = strings.TrimSpace(raw[:idx])
		}
		if raw == "" {
			continue
		}
		parts := strings.Fields(raw)
		if len(parts) < 1 || len(parts) > 2 {
			return nil, fmt.Errorf("keyset: line %d: expected 1 or 2 fields, got %d", line, len(parts))
		}
		pubBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("keyset: line %d: invalid hex: %w", line, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyset: line %d: key must be %d bytes", line, ed25519.PublicKeySize)
		}
		entry := keyEntry{pub: ed25519.PublicKey(pubBytes)}
		if len(parts) == 2 {
			t, err := time.Parse(time.RFC3339, parts[1])
			if err != nil {
				return nil, fmt.Errorf("keyset: line %d: invalid not-after %q: %w", line, parts[1], err)
			}
			entry.notAfter = t
		}
		ks.entries = append(ks.entries, entry)
	}
	if len(ks.entries) == 0 {
		return nil, fmt.Errorf("keyset: no keys found")
	}
	return ks, nil
}
