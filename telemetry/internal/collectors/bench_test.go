package collectors_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
)

// BenchmarkRegistry_CollectOnce verifies total collection time < 100ms on a typical host.
func BenchmarkRegistry_CollectOnce(b *testing.B) {
	r := collectors.NewRegistry(false, 0, nil)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.CollectOnce(ctx)
	}
}

// BenchmarkCPU measures /proc/stat parsing overhead.
func BenchmarkCPU(b *testing.B) {
	c := collectors.NewCPUCollectorWithPath("testdata/proc_stat")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Collect(ctx)
	}
}

// BenchmarkMemory measures /proc/meminfo parsing overhead.
func BenchmarkMemory(b *testing.B) {
	c := collectors.NewMemoryCollectorWithPath("testdata/proc_meminfo")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Collect(ctx)
	}
}
