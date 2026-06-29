package none

import (
	"context"
	"errors"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/provider"
)

func TestNoneProviderDiscoverReportsNone(t *testing.T) {
	caps, err := New().Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() returned err: %v", err)
	}
	if caps.Hypervisor != string(provider.KindNone) {
		t.Fatalf("expected hypervisor=none, got %q", caps.Hypervisor)
	}
}

func TestNoneProviderVMOpsRefuse(t *testing.T) {
	p := New()
	ctx := context.Background()
	if _, err := p.VMCreate(ctx, provider.VMSpec{}); !errors.Is(err, provider.ErrNotSupported) {
		t.Fatalf("VMCreate should return ErrNotSupported, got %v", err)
	}
	if _, err := p.CTCreate(ctx, provider.VMSpec{}); !errors.Is(err, provider.ErrNotSupported) {
		t.Fatalf("CTCreate should return ErrNotSupported, got %v", err)
	}
	if _, err := p.StorageList(ctx); !errors.Is(err, provider.ErrNotSupported) {
		t.Fatalf("StorageList should return ErrNotSupported, got %v", err)
	}
}
