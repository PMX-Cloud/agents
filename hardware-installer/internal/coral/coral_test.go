package coral

import (
	"reflect"
	"testing"
)

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
