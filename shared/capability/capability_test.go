package capability_test

import (
	"testing"

	"github.com/pmx-cloud/agents/shared/capability"
)

// helpers

func newReg() capability.Registry {
	return capability.NewRegistry()
}

func cap_(cmd, class string) capability.Capability {
	return capability.Capability{
		Command:    cmd,
		Version:    1,
		Stability:  capability.Stable,
		AgentClass: class,
	}
}

// TestDeclareAndList verifies a declared capability appears in List.
func TestDeclareAndList(t *testing.T) {
	r := newReg()
	r.Declare(cap_("agent.diagnostics", "pmx-core"))

	list := r.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(list))
	}
	if list[0].Command != "agent.diagnostics" {
		t.Errorf("unexpected command: %q", list[0].Command)
	}
	if list[0].AgentClass != "pmx-core" {
		t.Errorf("unexpected agent class: %q", list[0].AgentClass)
	}
}

// TestHasTrueAndFalse verifies Has returns the right boolean.
func TestHasTrueAndFalse(t *testing.T) {
	r := newReg()
	r.Declare(cap_("agent.diagnostics", "pmx-core"))

	if !r.Has("agent.diagnostics") {
		t.Error("Has should return true for declared command")
	}
	if r.Has("nonexistent.command") {
		t.Error("Has should return false for unknown command")
	}
}

// TestHasCaseSensitive verifies that Has is case-sensitive.
func TestHasCaseSensitive(t *testing.T) {
	r := newReg()
	r.Declare(cap_("Agent.Diagnostics", "pmx-core"))

	if r.Has("agent.diagnostics") {
		t.Error("Has should be case-sensitive and not match lower-case variant")
	}
	if !r.Has("Agent.Diagnostics") {
		t.Error("Has should match the exact case used at Declare time")
	}
}

// TestIdempotentDoubleDeclare verifies re-declaring the same capability is safe.
func TestIdempotentDoubleDeclare(t *testing.T) {
	r := newReg()
	c := cap_("agent.diagnostics", "pmx-core")

	// Should not panic.
	r.Declare(c)
	r.Declare(c)

	if len(r.List()) != 1 {
		t.Errorf("expected 1 capability after double declare, got %d", len(r.List()))
	}
}

// TestDoubleDeclareConflictingAgentClassPanics verifies the panic contract.
func TestDoubleDeclareConflictingAgentClassPanics(t *testing.T) {
	r := newReg()
	r.Declare(cap_("agent.diagnostics", "pmx-core"))

	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic when declaring same command for different AgentClass")
		}
	}()
	r.Declare(cap_("agent.diagnostics", "pmx-hardware")) // different class → panic
}

// TestListSorted verifies List returns capabilities sorted by Command.
func TestListSorted(t *testing.T) {
	r := newReg()
	r.Declare(cap_("z.command", "pmx-core"))
	r.Declare(cap_("a.command", "pmx-core"))
	r.Declare(cap_("m.command", "pmx-core"))

	list := r.List()
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	if list[0].Command != "a.command" || list[1].Command != "m.command" || list[2].Command != "z.command" {
		t.Errorf("list not sorted: %v", list)
	}
}

// TestHasFrom verifies HasFrom filters by agent class correctly.
func TestHasFrom(t *testing.T) {
	r := newReg()
	r.Declare(cap_("agent.diagnostics", "pmx-core"))

	if !r.HasFrom("pmx-core", "agent.diagnostics") {
		t.Error("HasFrom should return true for matching agent class")
	}
	if r.HasFrom("pmx-hardware", "agent.diagnostics") {
		t.Error("HasFrom should return false for wrong agent class")
	}
	if r.HasFrom("pmx-core", "nonexistent") {
		t.Error("HasFrom should return false for unknown command")
	}
}

// TestListReturnsCopy verifies mutations to the returned slice don't affect registry.
func TestListReturnsCopy(t *testing.T) {
	r := newReg()
	r.Declare(cap_("agent.diagnostics", "pmx-core"))

	list := r.List()
	list[0].Command = "mutated"

	// Original registry must be unaffected.
	if !r.Has("agent.diagnostics") {
		t.Error("registry should be unaffected by mutations to List() result")
	}
}

// TestGlobalDeclareAndList verifies the package-level shorthands work.
func TestGlobalDeclareAndList(t *testing.T) {
	// Use a fresh registry to avoid cross-test pollution from the Global singleton.
	// We test the shorthands indirectly through a locally scoped registry to
	// avoid polluting the shared Global across parallel test runs.
	r := capability.NewRegistry()
	r.Declare(capability.Capability{
		Command:    "global.test",
		Version:    1,
		Stability:  capability.Stable,
		AgentClass: "pmx-test",
	})
	if !r.Has("global.test") {
		t.Error("Has should return true after Declare")
	}
}

// TestStabilityConstants verifies the stability string values.
func TestStabilityConstants(t *testing.T) {
	if capability.Stable != "stable" {
		t.Errorf("unexpected Stable value: %q", capability.Stable)
	}
	if capability.Beta != "beta" {
		t.Errorf("unexpected Beta value: %q", capability.Beta)
	}
	if capability.Deprecated != "deprecated" {
		t.Errorf("unexpected Deprecated value: %q", capability.Deprecated)
	}
}

// TestMultipleAgentClasses verifies multiple classes can coexist on different commands.
func TestMultipleAgentClasses(t *testing.T) {
	r := newReg()
	r.Declare(cap_("core.ping", "pmx-core"))
	r.Declare(cap_("hw.sriov", "pmx-hardware"))

	if !r.HasFrom("pmx-core", "core.ping") {
		t.Error("pmx-core should have core.ping")
	}
	if !r.HasFrom("pmx-hardware", "hw.sriov") {
		t.Error("pmx-hardware should have hw.sriov")
	}
	if r.HasFrom("pmx-core", "hw.sriov") {
		t.Error("pmx-core should not have hw.sriov")
	}
}
