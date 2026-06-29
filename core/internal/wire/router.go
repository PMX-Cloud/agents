/*
Package wire implements the command dispatcher for pmx-core.

The Router maps command strings (e.g. "core.identify") to typed handler
functions. Unknown commands return a structured JSON error and are logged;
they do NOT cause a panic or silently succeed.
*/
package wire

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// Handler is the function signature for a command handler.
// It receives the verified envelope and returns a JSON-marshallable result or an error.
type Handler func(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error)

// ErrUnknownCommand is returned when no handler is registered for a command.
type ErrUnknownCommand struct {
	Command string
}

func (e *ErrUnknownCommand) Error() string {
	return fmt.Sprintf("UNKNOWN_COMMAND: %s", e.Command)
}

// Router maps command strings to handlers.
type Router struct {
	mu       sync.RWMutex
	handlers map[string]Handler
	log      *slog.Logger
}

// NewRouter creates an empty Router.
func NewRouter(log *slog.Logger) *Router {
	if log == nil {
		log = slog.Default()
	}
	return &Router{
		handlers: make(map[string]Handler),
		log:      log,
	}
}

// Register adds a handler for command. Panics if command is already registered
// (programming error, not a runtime error).
func (r *Router) Register(command string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.handlers[command]; exists {
		panic(fmt.Sprintf("wire: duplicate registration for command %q", command))
	}
	r.handlers[command] = h
}

// Dispatch routes the envelope to the registered handler.
// Returns (nil, *ErrUnknownCommand) for unregistered commands.
// All dispatches are logged with structured fields.
func (r *Router) Dispatch(ctx context.Context, env *envelope.Envelope) (json.RawMessage, error) {
	r.mu.RLock()
	h, ok := r.handlers[env.Command]
	r.mu.RUnlock()

	if !ok {
		r.log.Warn("wire: unknown command",
			"PMX_JOB_ID", env.JobID,
			"PMX_COMMAND", env.Command,
		)
		errPayload, _ := json.Marshal(map[string]string{
			"error":   "UNKNOWN_COMMAND",
			"command": env.Command,
		})
		return errPayload, &ErrUnknownCommand{Command: env.Command}
	}

	r.log.Info("wire: dispatch",
		"PMX_JOB_ID", env.JobID,
		"PMX_COMMAND", env.Command,
	)
	return h(ctx, env)
}

// Commands returns the sorted list of registered command names.
func (r *Router) Commands() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cmds := make([]string, 0, len(r.handlers))
	for k := range r.handlers {
		cmds = append(cmds, k)
	}
	return cmds
}
