/*
Package siblings implements sibling-agent lifecycle management for pmx-core.

pmx-core manages sibling units (pmx-telemetry, pmx-hypervisor, etc.) via the
D-Bus systemd interface, guarded by a polkit rule. The Go-level allowlist is the
FIRST gate; polkit is the SECOND gate (defence in depth).

No unit outside the allowlist may be touched, even by bug.
*/
package siblings

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// Manager manages the lifecycle of whitelisted sibling units.
type Manager struct {
	allowed           map[string]bool // exact service names
	ephemeralPrefixes []string        // template prefixes e.g. "pmx-hardware-installer@"
	log               *slog.Logger
}

// NewManager creates a sibling manager with the given allow-lists.
func NewManager(allowed, ephemeralTemplates []string, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		allowed: make(map[string]bool, len(allowed)),
		log:     log,
	}
	for _, s := range allowed {
		m.allowed[s] = true
	}
	for _, t := range ephemeralTemplates {
		// Strip trailing ".service" if present to get the prefix.
		prefix := strings.TrimSuffix(t, ".service")
		// Template units look like "pmx-hardware-installer@.service" — keep the @.
		m.ephemeralPrefixes = append(m.ephemeralPrefixes, prefix)
	}
	return m
}

// Allow returns true if unit is in the allowlist or matches an ephemeral template.
func (m *Manager) Allow(unit string) bool {
	if m.allowed[unit] {
		return true
	}
	for _, prefix := range m.ephemeralPrefixes {
		if strings.HasPrefix(unit, prefix) {
			return true
		}
	}
	return false
}

// Start enables and starts unit. Requires unit to be in the allowlist.
func (m *Manager) Start(ctx context.Context, unit string) error {
	if err := m.checkAllowed(unit); err != nil {
		return err
	}
	return m.systemctl(ctx, "start", unit)
}

// Stop stops unit.
func (m *Manager) Stop(ctx context.Context, unit string) error {
	if err := m.checkAllowed(unit); err != nil {
		return err
	}
	return m.systemctl(ctx, "stop", unit)
}

// Enable enables unit (persistent across reboots).
func (m *Manager) Enable(ctx context.Context, unit string) error {
	if err := m.checkAllowed(unit); err != nil {
		return err
	}
	return m.systemctl(ctx, "enable", "--now", unit)
}

// Disable disables unit.
func (m *Manager) Disable(ctx context.Context, unit string) error {
	if err := m.checkAllowed(unit); err != nil {
		return err
	}
	return m.systemctl(ctx, "disable", "--now", unit)
}

// Restart restarts unit.
func (m *Manager) Restart(ctx context.Context, unit string) error {
	if err := m.checkAllowed(unit); err != nil {
		return err
	}
	return m.systemctl(ctx, "restart", unit)
}

// DaemonReload reloads systemd unit files (needed after new unit file installation).
func (m *Manager) DaemonReload(ctx context.Context) error {
	return m.systemctl(ctx, "daemon-reload")
}

// Status returns the ActiveState of unit.
func (m *Manager) Status(ctx context.Context, unit string) (string, error) {
	if err := m.checkAllowed(unit); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("siblings: systemctl show %s: %w", unit, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// checkAllowed returns an error if unit is not in the allowlist.
func (m *Manager) checkAllowed(unit string) error {
	if !m.Allow(unit) {
		return fmt.Errorf("siblings: unit %q is not in the allowlist (house rule P3)", unit)
	}
	return nil
}

// systemctl runs systemctl with the given arguments.
func (m *Manager) systemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("siblings: systemctl %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	m.log.Info("siblings: systemctl", "args", args)
	return nil
}
