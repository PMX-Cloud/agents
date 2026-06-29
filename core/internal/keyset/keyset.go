/*
Package keyset implements the core.keyset.update command handler.

The rotation flow:
 1. Verify the rotation envelope is signed by a currently-active key (not the
    to-be-retired one — the backend ensures the right key signs the rotation command).
 2. Parse the new keyset from envelope.Params["keys"].
 3. Validate: ≥ 1 currently-active key in the new set (lockout prevention).
 4. Atomic-write to a temp file in /etc/pmx-cloud/, fsync, rename.
 5. Reload the in-memory KeySet via the supplied Update() callback.

If any step fails, the old keyset is left intact and the error is returned.
*/
package keyset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

// Rotator handles keyset update operations.
type Rotator struct {
	// KeysetPath is the file path of the keyset (e.g. /etc/pmx-cloud/keyset.pub).
	KeysetPath string
	// CurrentKeySet is the live keyset used for verification; it is updated atomically.
	CurrentKeySet *envpkg.KeySet
}

// Handle is the wire.Handler for core.keyset.update.
func (r *Rotator) Handle(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
	// Extract the new keyset lines from params.
	raw, ok := env.Params["keys"]
	if !ok {
		return errorJSON("MISSING_PARAM", "params.keys is required"), nil
	}

	var lines []string
	switch v := raw.(type) {
	case []interface{}:
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return errorJSON("BAD_PARAM", fmt.Sprintf("params.keys[%d] is not a string", i)), nil
			}
			lines = append(lines, s)
		}
	case string:
		lines = strings.Split(v, "\n")
	default:
		return errorJSON("BAD_PARAM", "params.keys must be a string or array of strings"), nil
	}

	content := strings.Join(lines, "\n")

	// Parse and validate the new keyset.
	newKS, err := envpkg.ParseKeySet(content)
	if err != nil {
		return errorJSON("INVALID_KEYSET", err.Error()), nil
	}

	if newKS.Len() == 0 {
		return errorJSON("EMPTY_KEYSET", "update would leave 0 active keys — rejected"), nil
	}

	// Write atomically.
	if err := atomicWriteKeyset(r.KeysetPath, content); err != nil {
		return nil, fmt.Errorf("keyset: write: %w", err)
	}

	// Reload in-memory keyset.
	if err := r.CurrentKeySet.Update(newKS); err != nil {
		return nil, fmt.Errorf("keyset: reload: %w", err)
	}

	result, _ := json.Marshal(map[string]interface{}{
		"ok":       true,
		"keyCount": newKS.Len(),
	})
	return result, nil
}

// atomicWriteKeyset writes content to path using temp-file + rename.
func atomicWriteKeyset(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyset-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.WriteString(content); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func errorJSON(code, message string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"error": code, "message": message})
	return b
}
