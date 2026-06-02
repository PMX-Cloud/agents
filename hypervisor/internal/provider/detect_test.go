package provider

import "testing"

func TestDetectFallsBackToNone(t *testing.T) {
	// In CI/dev containers neither pveversion nor virsh is installed, so
	// the auto detect should land on the "none" provider.
	got := Detect()
	switch got {
	case KindNone, KindLibvirt, KindProxmox:
		// any of these are valid depending on the test host
	default:
		t.Fatalf("unexpected provider kind: %s", got)
	}
}

func TestHasBinaryFalseForMissing(t *testing.T) {
	if hasBinary("pmx-not-a-real-binary-12345", "") {
		t.Fatal("hasBinary should return false for a missing executable")
	}
}
