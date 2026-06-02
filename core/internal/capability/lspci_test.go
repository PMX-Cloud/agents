package capability_test

import (
	"testing"

	"github.com/pmx-cloud/agents/core/internal/capability"
)

const lspciOutput = `Slot:	00:02.0
Class:	VGA compatible controller
Vendor:	Intel Corporation
Device:	UHD Graphics 620
SVendor:	Lenovo
SDevice:	UHD Graphics 620
Rev:	07

Slot:	01:00.0
Class:	3D controller
Vendor:	NVIDIA Corporation
Device:	GeForce GTX 1050 Ti Mobile
SVendor:	Lenovo
SDevice:	GeForce GTX 1050 Ti
Rev:	a1

Slot:	00:1f.3
Class:	Audio device
Vendor:	Intel Corporation
Device:	Sunrise Point-LP HD Audio
`

func TestParseLspciOutput_MultiGPU(t *testing.T) {
	gpus := capability.ParseLspciOutput(lspciOutput)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs (VGA + 3D), got %d", len(gpus))
	}
	for _, g := range gpus {
		if g.Vendor == "" {
			t.Error("GPU vendor must not be empty")
		}
		if g.Model == "" {
			t.Error("GPU model must not be empty")
		}
	}
}

func TestParseLspciOutput_NoGPU(t *testing.T) {
	out := `Slot:	00:1f.3
Class:	Audio device
Vendor:	Intel Corporation
Device:	HD Audio
`
	gpus := capability.ParseLspciOutput(out)
	if len(gpus) != 0 {
		t.Fatalf("expected 0 GPUs for non-VGA devices, got %d", len(gpus))
	}
}

func TestParseLspciOutput_Empty(t *testing.T) {
	gpus := capability.ParseLspciOutput("")
	if gpus == nil {
		t.Fatal("nil slice from empty output")
	}
	if len(gpus) != 0 {
		t.Fatal("empty output must yield 0 GPUs")
	}
}

func TestParseLspciOutput_DisplayClass(t *testing.T) {
	out := `Slot:	00:02.0
Class:	Display controller
Vendor:	AMD
Device:	Radeon RX 580
`
	gpus := capability.ParseLspciOutput(out)
	if len(gpus) != 1 {
		t.Fatalf("expected 1 GPU for Display controller, got %d", len(gpus))
	}
}

func TestParseLspciOutput_NoFlushAtEnd(t *testing.T) {
	// Output without trailing blank line — flush must still be called at end.
	out := "Slot:\t00:02.0\nClass:\tVGA compatible controller\nVendor:\tIntel\nDevice:\tHD Graphics\n"
	gpus := capability.ParseLspciOutput(out)
	if len(gpus) != 1 {
		t.Fatalf("expected 1 GPU without trailing newline, got %d", len(gpus))
	}
}
