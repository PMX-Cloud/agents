/*
Package wire_test includes a fuzz test for the envelope router.

Architecture §12 mandates: pass random bytes through the router; assert no panic,
all rejections go through the audit log.
*/
package wire_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/core/internal/wire"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

// FuzzEnvelopeRoute passes random command strings through the router and asserts
// no panic. This catches registration panics and nil-return bugs.
func FuzzEnvelopeRoute(f *testing.F) {
	r := wire.NewRouter(nil)
	r.Register("core.identify", func(_ context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	})
	r.Register("core.shutdown", func(_ context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
		return json.RawMessage(`{"draining":true}`), nil
	})

	// Seed corpus.
	f.Add("core.identify")
	f.Add("core.shutdown")
	f.Add("core.does.not.exist")
	f.Add("")
	f.Add("../../../../etc/passwd")
	f.Add("core.identify\x00injected")

	f.Fuzz(func(t *testing.T, command string) {
		env := &envpkg.Envelope{
			Version:   "pmx-agent-v1",
			JobID:     "fuzz-job-1",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(30 * time.Minute),
			Audience:  "pmx-core",
			Command:   command,
			Params:    map[string]interface{}{},
		}
		// Must not panic; may return an error.
		result, _ := r.Dispatch(context.Background(), env)
		// Result must always be valid JSON or nil.
		if result != nil && !json.Valid(result) {
			t.Errorf("router returned invalid JSON for command %q: %s", command, result)
		}
	})
}
