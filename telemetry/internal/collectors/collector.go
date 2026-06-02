// Package collectors defines the Collector interface and the Metric type.
// All collectors are read-only — no writes to /proc, /sys, or anywhere else.
package collectors

import (
	"context"
	"time"
)

// Metric is a single timestamped observation.
type Metric struct {
	Name      string
	Value     float64
	Timestamp time.Time
	Labels    map[string]string
}

// Collector produces a slice of Metrics on demand.
type Collector interface {
	// Name returns the collector's identifier (used in logs and "collector.failed" events).
	Name() string
	// Collect reads the relevant /proc or /sys files and returns Metrics.
	// Must return quickly (< 20ms). On error, returns a partial slice + error;
	// the caller emits a collector.failed event and continues.
	Collect(ctx context.Context) ([]Metric, error)
}
