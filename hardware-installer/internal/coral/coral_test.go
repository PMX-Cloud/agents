package coral

import (
	"reflect"
	"testing"
)

func TestResolveInstallPlan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		interfaceName  string
		packages       []string
		verifyDKMS     bool
		rebootRequired bool
	}{
		{
			name:          "USB uses only the standard runtime",
			interfaceName: "usb",
			packages:      []string{"libedgetpu1-std"},
		},
		{
			name:          "empty defaults to USB",
			interfaceName: "",
			packages:      []string{"libedgetpu1-std"},
		},
		{
			name:           "M2 includes the PCIe driver and standard runtime",
			interfaceName:  "m2",
			packages:       []string{"gasket-dkms", "libedgetpu1-std"},
			verifyDKMS:     true,
			rebootRequired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan, err := resolveInstallPlan(tt.interfaceName)
			if err != nil {
				t.Fatalf("resolveInstallPlan() error = %v", err)
			}
			if !reflect.DeepEqual(plan.packages, tt.packages) {
				t.Fatalf("packages = %#v, want %#v", plan.packages, tt.packages)
			}
			if plan.verifyDKMS != tt.verifyDKMS {
				t.Fatalf("verifyDKMS = %v, want %v", plan.verifyDKMS, tt.verifyDKMS)
			}
			if plan.rebootRequired != tt.rebootRequired {
				t.Fatalf("rebootRequired = %v, want %v", plan.rebootRequired, tt.rebootRequired)
			}
		})
	}
}

func TestResolveInstallPlanRejectsUnknownInterface(t *testing.T) {
	t.Parallel()

	if _, err := resolveInstallPlan("pcie"); err == nil {
		t.Fatal("resolveInstallPlan() error = nil, want validation error")
	}
}

func TestParseCoralPCIIDs(t *testing.T) {
	t.Parallel()

	raw := `
00:01.0 VGA compatible controller [0300]: NVIDIA Corporation Device [10de:1fb8]
03:00.0 Co-processor [0b40]: Device [1ac1:089a]
04:00.0 Co-processor [0b40]: Google Inc. Device [1ac1:089a]
04:00.0 Co-processor [0b40]: Google Inc. Device [1ac1:089a]
`
	got := parseCoralPCIIDs(raw)
	want := []string{"03:00.0", "04:00.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCoralPCIIDs() = %#v, want %#v", got, want)
	}
}
