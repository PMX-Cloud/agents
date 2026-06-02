package kernel

import (
	"context"
	"testing"
)

func TestLoadModuleRejectsNotAllowlisted(t *testing.T) {
	t.Parallel()

	_, err := LoadModule(context.Background(), Params{
		ModprobePath:   "/usr/bin/true",
		AllowedModules: []string{"vfio"},
	}, LoadRequest{Module: "zfs"}, nil)
	if err == nil {
		t.Fatal("expected allowlist error")
	}
}

func TestLoadModuleSuccess(t *testing.T) {
	t.Parallel()

	res, err := LoadModule(context.Background(), Params{
		ModprobePath:   "/usr/bin/true",
		AllowedModules: []string{"vfio"},
	}, LoadRequest{Module: "vfio"}, nil)
	if err != nil {
		t.Fatalf("LoadModule() error = %v", err)
	}
	if !res.Loaded {
		t.Fatal("expected Loaded=true")
	}
}
