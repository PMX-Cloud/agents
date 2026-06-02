// Package capability provides a thread-safe registry of commands that each
// agent declares at boot. The backend can query pmx-core for the merged set
// to track capability drift across rollouts.
package capability

import (
	"fmt"
	"sort"
	"sync"
)

// Stability describes how mature a capability is.
type Stability string

const (
	Stable     Stability = "stable"
	Beta       Stability = "beta"
	Deprecated Stability = "deprecated"
)

// Capability describes a single command that an agent class supports.
type Capability struct {
	Command    string
	Version    int
	Stability  Stability
	AgentClass string
}

// Registry is a thread-safe store of Capability values.
type Registry interface {
	// Declare registers a capability. It panics if the same command is declared
	// with a different AgentClass (programming error). It is idempotent when
	// called with the same value.
	Declare(c Capability)

	// List returns a sorted copy of all registered capabilities (sorted by
	// Command string).
	List() []Capability

	// Has reports whether a command (case-sensitive) is registered.
	Has(command string) bool

	// HasFrom reports whether the given agentClass has registered the command.
	HasFrom(agentClass, command string) bool
}

type registry struct {
	mu    sync.RWMutex
	store map[string]Capability // keyed by Command
}

// NewRegistry returns a new, empty Registry.
func NewRegistry() Registry {
	return &registry{store: make(map[string]Capability)}
}

func (r *registry) Declare(c Capability) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.store[c.Command]
	if !ok {
		r.store[c.Command] = c
		return
	}

	// Same command declared again — must match AgentClass, otherwise it is a
	// programming error (two different agents claiming the same command name).
	if existing.AgentClass != c.AgentClass {
		panic(fmt.Sprintf(
			"capability: command %q already declared by agent class %q; cannot re-declare for %q",
			c.Command, existing.AgentClass, c.AgentClass,
		))
	}

	// Idempotent: same value, no-op.
	r.store[c.Command] = c
}

func (r *registry) List() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Capability, 0, len(r.store))
	for _, c := range r.store {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Command < out[j].Command
	})
	return out
}

func (r *registry) Has(command string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.store[command]
	return ok
}

func (r *registry) HasFrom(agentClass, command string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.store[command]
	return ok && c.AgentClass == agentClass
}

// Global is the package-level registry. Agents register capabilities into it
// from their init() functions.
var Global Registry = NewRegistry()

// Declare is a shorthand for Global.Declare(c).
func Declare(c Capability) {
	Global.Declare(c)
}

// List is a shorthand for Global.List().
func List() []Capability {
	return Global.List()
}
