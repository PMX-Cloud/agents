package apt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTuneWritesDefaultsAndPins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	disableInstall := false
	res, err := Tune(context.Background(), Params{
		AptGetPath:  "/usr/bin/false",
		ConfigDir:   dir,
		OutputLimit: 1024,
	}, Request{
		InstallTransport: &disableInstall,
		Pins: []Pin{{
			Name:    "nvidia",
			Content: "Package: nvidia-driver\nPin: release a=bookworm\nPin-Priority: 800",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("Tune() error = %v", err)
	}
	if !res.Changed {
		t.Fatal("expected changed=true")
	}
	for _, file := range []string{
		"99-pmx-cloud-performance",
		"99-pmx-cloud-no-languages",
		"99-pmx-cloud-pin-nvidia",
	} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Fatalf("expected %s to exist: %v", file, err)
		}
	}

	res2, err := Tune(context.Background(), Params{
		AptGetPath:  "/usr/bin/false",
		ConfigDir:   dir,
		OutputLimit: 1024,
	}, Request{InstallTransport: &disableInstall}, nil)
	if err != nil {
		t.Fatalf("second Tune() error = %v", err)
	}
	if res2.Changed {
		t.Fatal("expected second call to be idempotent")
	}
}

func TestTuneRejectsInvalidPinName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	disableInstall := false
	_, err := Tune(context.Background(), Params{ConfigDir: dir}, Request{
		InstallTransport: &disableInstall,
		Pins:             []Pin{{Name: "../escape", Content: "x"}},
	}, nil)
	if err == nil {
		t.Fatal("expected invalid pin name error")
	}
}
