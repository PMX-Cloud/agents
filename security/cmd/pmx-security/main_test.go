package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

func TestUnsupportedCommandReturnsError(t *testing.T) {
	h := &securityHandler{log: slog.Default()}
	_, err := h.dispatch(context.Background(), &envpkg.Envelope{Command: "security.nope"})
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED") {
		t.Fatalf("expected unsupported command error, got %v", err)
	}
}
