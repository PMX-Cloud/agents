/*
Package thresholds implements local threshold evaluation (architecture §5.2, Task 4).

The backend pushes a threshold set via telemetry.thresholds.set; the engine
evaluates each threshold on every sample batch and emits host.alert events when
a condition holds for for_seconds, and host.alert.cleared when it recovers.

Key design decisions:
  - Threshold sets are swapped atomically (pointer swap). Old threshold state is GC'd.
  - Alert fires exactly once per crossing (debounce: don't re-alert until cleared + 60s).
  - Bad threshold operators are rejected at Set() time; the agent never starts using a
    partially-valid set (all-or-nothing validation).
  - Evaluation runs on its own goroutine; collectors don't wait for it.
*/
package thresholds

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
)

// Severity levels for alerts.
type Severity string

const (
	SeverityWarn Severity = "warn"
	SeverityPage Severity = "page"
)

// Op is a threshold comparison operator.
type Op string

const (
	OpLT        Op = "<"
	OpGT        Op = ">"
	OpLTE       Op = "<="
	OpGTE       Op = ">="
	OpRateBelow Op = "rate-below"
	OpRateAbove Op = "rate-above"
)

// Threshold is a single rule from the backend.
type Threshold struct {
	ID         string   `json:"id"`
	Metric     string   `json:"metric"`
	Op         Op       `json:"op"`
	Value      float64  `json:"value"`
	ForSeconds float64  `json:"for_seconds"`
	Severity   Severity `json:"severity"`
}

// Alert is emitted when a threshold fires or clears.
type Alert struct {
	ThresholdID string
	Metric      string
	Value       float64
	Severity    Severity
	Cleared     bool
	FiredAt     time.Time
}

// thresholdState tracks evaluation state for one threshold.
type thresholdState struct {
	def          Threshold
	holdingSince time.Time // when condition first became true; zero = not holding
	firedAt      time.Time // when the alert was last emitted; zero = not fired
	cleared      bool      // whether a "cleared" event has been sent after the last fire
}

// Engine evaluates a threshold set against a stream of metric samples.
type Engine struct {
	// active is an atomically-swapped *[]*thresholdState.
	active unsafe.Pointer

	// AlertCh receives alert events. Buffered to avoid blocking evaluation.
	AlertCh chan Alert

	debounce time.Duration
}

// NewEngine creates an Engine with an empty threshold set.
func NewEngine() *Engine {
	e := &Engine{
		AlertCh:  make(chan Alert, 256),
		debounce: 60 * time.Second,
	}
	empty := make([]*thresholdState, 0)
	atomic.StorePointer(&e.active, unsafe.Pointer(&empty))
	return e
}

// Set atomically replaces the threshold set. All thresholds are validated first;
// if any are invalid the call returns an error and the old set is unchanged.
func (e *Engine) Set(thresholds []Threshold) error {
	for i, t := range thresholds {
		if err := validateThreshold(t); err != nil {
			return fmt.Errorf("threshold[%d] %q: %w", i, t.ID, err)
		}
	}
	states := make([]*thresholdState, len(thresholds))
	for i, t := range thresholds {
		states[i] = &thresholdState{def: t}
	}
	atomic.StorePointer(&e.active, unsafe.Pointer(&states))
	return nil
}

// SetFromJSON parses a JSON threshold array and calls Set.
func (e *Engine) SetFromJSON(data []byte) error {
	var thresholds []Threshold
	if err := json.Unmarshal(data, &thresholds); err != nil {
		return fmt.Errorf("thresholds: parse JSON: %w", err)
	}
	return e.Set(thresholds)
}

// Evaluate runs the threshold engine against a fresh batch of metrics.
// This must be called from a single goroutine (or with external synchronisation).
func (e *Engine) Evaluate(metrics []collectors.Metric) {
	// Build a fast metric lookup: name → latest value.
	latest := map[string]float64{}
	for _, m := range metrics {
		// Last value wins if same name appears multiple times.
		latest[m.Name] = m.Value
	}

	statesPtr := (*[]*thresholdState)(atomic.LoadPointer(&e.active))
	if statesPtr == nil {
		return
	}
	states := *statesPtr
	now := time.Now()

	for _, s := range states {
		val, ok := latest[s.def.Metric]
		if !ok {
			continue // metric not in this batch
		}

		holds := evaluate(s.def.Op, val, s.def.Value)
		forDur := time.Duration(s.def.ForSeconds * float64(time.Second))

		if holds {
			if s.holdingSince.IsZero() {
				s.holdingSince = now
			}
			// Fire alert if condition has held long enough AND not already fired recently.
			if now.Sub(s.holdingSince) >= forDur {
				shouldFire := s.firedAt.IsZero() ||
					(s.cleared && now.Sub(s.firedAt) >= e.debounce)
				if shouldFire {
					s.firedAt = now
					s.cleared = false
					select {
					case e.AlertCh <- Alert{
						ThresholdID: s.def.ID,
						Metric:      s.def.Metric,
						Value:       val,
						Severity:    s.def.Severity,
						FiredAt:     now,
					}:
					default:
					}
				}
			}
		} else {
			// Condition not holding.
			if !s.holdingSince.IsZero() {
				s.holdingSince = time.Time{}
			}
			// Send cleared event if we had previously fired and not yet cleared.
			if !s.firedAt.IsZero() && !s.cleared {
				s.cleared = true
				select {
				case e.AlertCh <- Alert{
					ThresholdID: s.def.ID,
					Metric:      s.def.Metric,
					Value:       val,
					Severity:    s.def.Severity,
					Cleared:     true,
					FiredAt:     now,
				}:
				default:
				}
			}
		}
	}
}

// evaluate computes whether val op threshold holds.
func evaluate(op Op, val, threshold float64) bool {
	switch op {
	case OpLT:
		return val < threshold
	case OpGT:
		return val > threshold
	case OpLTE:
		return val <= threshold
	case OpGTE:
		return val >= threshold
	case OpRateBelow:
		return val < threshold
	case OpRateAbove:
		return val > threshold
	}
	return false
}

// validateThreshold checks that a threshold definition is sane.
func validateThreshold(t Threshold) error {
	if t.ID == "" {
		return fmt.Errorf("id is required")
	}
	if t.Metric == "" {
		return fmt.Errorf("metric is required")
	}
	switch t.Op {
	case OpLT, OpGT, OpLTE, OpGTE, OpRateBelow, OpRateAbove:
		// valid
	default:
		return fmt.Errorf("unknown op %q", t.Op)
	}
	if t.ForSeconds < 0 {
		return fmt.Errorf("for_seconds must be ≥ 0")
	}
	switch t.Severity {
	case SeverityWarn, SeverityPage:
	default:
		return fmt.Errorf("unknown severity %q", t.Severity)
	}
	return nil
}
