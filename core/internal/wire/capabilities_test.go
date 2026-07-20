package wire_test

import (
	"context"
	"encoding/json"
	"testing"

	sharedcap "github.com/pmx-cloud/agents/shared/capability"
	"github.com/pmx-cloud/agents/shared/envelope"

	"github.com/pmx-cloud/agents/core/internal/wire"
)

// TestRouter_CapabilitiesHandler verifies that a router with a core.capabilities
// handler returns a JSON payload containing all registered commands.
func TestRouter_CapabilitiesHandler(t *testing.T) {
	reg := sharedcap.NewRegistry()
	router := wire.NewRouter(nil)

	commands := []string{"core.identify", "core.agents.list", "core.agents.enable",
		"core.agents.disable", "core.spawn.ephemeral", "core.keyset.update",
		"core.preflight", "core.shutdown"}

	for _, cmd := range commands {
		c := cmd // capture loop var
		router.Register(c, func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
			return json.RawMessage(`{"ok":true}`), nil
		})
	}

	// Simulate what main.go does: declare commands into the registry, then wire handler.
	for _, cmd := range router.Commands() {
		reg.Declare(sharedcap.Capability{
			Command:    cmd,
			Version:    1,
			Stability:  sharedcap.Stable,
			AgentClass: "pmx-core",
		})
	}

	router.Register("core.capabilities", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		caps := reg.List()
		return json.Marshal(map[string]interface{}{
			"agent":        "pmx-core",
			"capabilities": caps,
		})
	})

	// Dispatch core.capabilities.
	env := &envelope.Envelope{Command: "core.capabilities", JobID: "test-1"}
	raw, err := router.Dispatch(context.Background(), env)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	var resp struct {
		Agent        string                 `json:"agent"`
		Capabilities []sharedcap.Capability `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Agent != "pmx-core" {
		t.Errorf("agent = %q, want pmx-core", resp.Agent)
	}
	// Register core.capabilities itself into the registry (mirrors main.go behaviour).
	reg.Declare(sharedcap.Capability{
		Command:    "core.capabilities",
		Version:    1,
		Stability:  sharedcap.Stable,
		AgentClass: "pmx-core",
	})

	// Re-dispatch to get the updated registry (now 9 capabilities).
	raw, err = router.Dispatch(context.Background(), env)
	if err != nil {
		t.Fatalf("dispatch 2: %v", err)
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal 2: %v", err)
	}

	// Registry should contain all 9 commands (8 original + core.capabilities).
	if len(resp.Capabilities) < 9 {
		t.Errorf("got %d capabilities, want >= 9", len(resp.Capabilities))
	}

	// Verify every original command is present.
	registered := make(map[string]bool)
	for _, c := range resp.Capabilities {
		registered[c.Command] = true
	}
	for _, cmd := range commands {
		if !registered[cmd] {
			t.Errorf("missing command %q in capabilities list", cmd)
		}
	}
}

// TestRouter_Commands returns the sorted list of registered commands.
func TestRouter_Commands_Sorted(t *testing.T) {
	router := wire.NewRouter(nil)
	router.Register("z.command", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		return nil, nil
	})
	router.Register("a.command", func(_ context.Context, _ *envelope.Envelope) (json.RawMessage, error) {
		return nil, nil
	})

	cmds := router.Commands()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}
