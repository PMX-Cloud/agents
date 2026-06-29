// registry.go holds the canonical set of collectors and the collection loop.
package collectors

import (
	"context"
	"log/slog"
	"time"
)

// Registry runs all collectors on a fixed interval and sends batched samples
// to an output channel. It never blocks the caller.
type Registry struct {
	collectors []Collector
	interval   time.Duration
	out        chan []Metric
	log        *slog.Logger
}

// NewRegistry creates a Registry with the standard set of collectors.
func NewRegistry(proxmoxEnabled bool, interval time.Duration, log *slog.Logger) *Registry {
	if log == nil {
		log = slog.Default()
	}
	cs := []Collector{
		NewCPUCollector(),
		NewMemoryCollector(),
		NewLoadCollector(),
		NewDiskIOCollector(),
		NewNetIOCollector(),
		NewFilesystemCollector(),
		NewKernelEventsCollector(),
		NewAgentProcCollector(),
		NewProxmoxCollector(proxmoxEnabled),
	}
	return &Registry{
		collectors: cs,
		interval:   interval,
		out:        make(chan []Metric, 256),
		log:        log,
	}
}

// Out returns the channel that receives batched Metric slices.
func (r *Registry) Out() <-chan []Metric { return r.out }

// Run starts the collection loop. It returns when ctx is cancelled.
func (r *Registry) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collect(ctx)
		}
	}
}

// CollectOnce runs all collectors once synchronously (for snapshot command).
func (r *Registry) CollectOnce(ctx context.Context) []Metric {
	var all []Metric
	for _, c := range r.collectors {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		metrics, err := c.Collect(cctx)
		cancel()
		if err != nil {
			r.log.Warn("collector failed", "collector", c.Name(), "err", err)
			// Emit a collector.failed event metric.
			all = append(all, Metric{
				Name:      "collector_failed",
				Value:     1,
				Timestamp: time.Now(),
				Labels:    map[string]string{"collector": c.Name(), "error": err.Error()},
			})
			continue
		}
		all = append(all, metrics...)
	}
	return all
}

func (r *Registry) collect(ctx context.Context) {
	batch := r.CollectOnce(ctx)
	select {
	case r.out <- batch:
	default:
		// Drop if the channel is full (backpressure protection for collectors).
		r.log.Warn("collectors: output channel full, dropping batch", "metrics", len(batch))
	}
}
