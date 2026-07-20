/*
Package drain implements the core.shutdown graceful drain (architecture §5.1, Task 10).

Drain flow:
 1. Set the draining flag — new envelopes are rejected with DRAINING.
 2. Signal the backend via the next heartbeat (the heartbeat now includes "draining: true").
    The backend stops dispatching new jobs and sends *.drain to each sibling.
 3. Wait up to 5 minutes for the backend to confirm all siblings are idle.
 4. systemctl stop each sibling.
 5. Exit 0.
*/
package drain

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/pmx-cloud/agents/core/internal/siblings"
	envpkg "github.com/pmx-cloud/agents/shared/envelope"
)

const (
	// MaxDrainWait is how long we wait for siblings to go idle before forcing stop.
	MaxDrainWait = 5 * time.Minute
)

// Drainer manages the graceful drain sequence.
type Drainer struct {
	draining int32 // atomic flag; 1 = draining
	siblings *siblings.Manager
	log      *slog.Logger
	// cancelRoot cancels the root context, causing pmx-core to exit.
	cancelRoot context.CancelFunc
}

// NewDrainer creates a Drainer.
func NewDrainer(mgr *siblings.Manager, cancelRoot context.CancelFunc, log *slog.Logger) *Drainer {
	if log == nil {
		log = slog.Default()
	}
	return &Drainer{
		siblings:   mgr,
		cancelRoot: cancelRoot,
		log:        log,
	}
}

// IsDraining returns true if a drain has been initiated.
func (d *Drainer) IsDraining() bool {
	return atomic.LoadInt32(&d.draining) == 1
}

// Handle is the wire.Handler for core.shutdown.
// It starts the drain asynchronously and returns immediately with a "draining" ack.
func (d *Drainer) Handle(ctx context.Context, env *envpkg.Envelope) (json.RawMessage, error) {
	if d.IsDraining() {
		result, _ := json.Marshal(map[string]string{"status": "already_draining"})
		return result, nil
	}

	d.log.Info("drain: initiating graceful shutdown", "PMX_JOB_ID", env.JobID)
	atomic.StoreInt32(&d.draining, 1)

	go d.run()

	result, _ := json.Marshal(map[string]string{"status": "draining"})
	return result, nil
}

// run executes the drain sequence in a background goroutine.
func (d *Drainer) run() {
	ctx, cancel := context.WithTimeout(context.Background(), MaxDrainWait)
	defer cancel()

	d.log.Info("drain: waiting for in-flight jobs to complete", "timeout", MaxDrainWait)
	// In a full implementation, this would poll the backend for sibling idle status.
	// For the initial implementation, we wait a fixed grace period.
	select {
	case <-ctx.Done():
		d.log.Warn("drain: timeout waiting for siblings")
	case <-time.After(2 * time.Second): // short grace; real impl polls backend
		d.log.Info("drain: grace period elapsed")
	}

	// Stop each whitelisted sibling.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()

	for _, unit := range d.allowedUnits() {
		d.log.Info("drain: stopping sibling", "unit", unit)
		if err := d.siblings.Stop(stopCtx, unit); err != nil {
			// Log but don't abort — stop as many as we can.
			d.log.Warn("drain: stop sibling failed", "unit", unit, "err", err)
		}
	}

	d.log.Info("drain: complete, exiting")
	// Cancel the root context to trigger a clean exit of pmx-core.
	d.cancelRoot()
}

// allowedUnits returns the list of sibling units to stop during drain.
// This is the same allowlist from the config.
func (d *Drainer) allowedUnits() []string {
	return []string{
		"pmx-telemetry.service",
		"pmx-hypervisor.service",
		"pmx-storage.service",
		"pmx-network.service",
		"pmx-security.service",
		"pmx-backup.service",
	}
}

// DrainStatus is included in heartbeat payloads to inform the backend.
type DrainStatus struct {
	Draining bool `json:"draining"`
}

// Status returns the current drain status for heartbeat inclusion.
func (d *Drainer) Status() DrainStatus {
	return DrainStatus{Draining: d.IsDraining()}
}

// RejectIfDraining returns an error JSON payload if draining is active.
// The wsclient OnEnvelope handler should call this before dispatching.
func (d *Drainer) RejectIfDraining() (json.RawMessage, bool) {
	if !d.IsDraining() {
		return nil, false
	}
	payload, _ := json.Marshal(map[string]string{
		"error":   "DRAINING",
		"message": fmt.Sprintf("pmx-core is draining, no new commands accepted"),
	})
	return payload, true
}
